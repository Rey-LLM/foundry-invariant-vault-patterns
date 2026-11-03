"""Preset 08: economic read-reentrancy through view functions.

A view like ``totalAssets``, ``convertToAssets``, ``pricePerShare`` or ``getReserves`` is read by other
protocols to value a position or a price. Read-only reentrancy is when that view returns a value that is
true neither before a flow nor after it, but in the middle of one - and a reader acts on it. It happens
when a function sends value to the caller *before* it finishes updating its accounting: the payment hands
control to the caller (a native ``receive`` / ``fallback``, an ERC-777 ``tokensReceived``), and at that
instant the contract has, say, already sent out the assets but not yet burned the shares, so
``pricePerShare`` reads low. A lending market that reads that price liquidates; an AMM that reads those
reserves misprices.

The defect is an ordering one: an external payment to the caller appears before the state write that an
economic view depends on. The fix is checks-effects-interactions (settle first, pay last) or a read lock
the views respect.

This module does three jobs for the parser and the injector:

1. ``detect_payout_before_settle_ast`` walks a solc AST function body in source order and reports whether
   a payment to the caller (native ``call{value:}`` / ``transfer`` / ``send``, or an ERC-20/777 token
   transfer to a non-``this`` recipient) comes before a write to an accounting state variable.
2. ``analyze`` decides whether a target gets the preset: it needs that ordering defect and at least one
   economic view a reader would read mid-payment.
3. The injector reuses the Preset 04 hook probe to observe the native payment: ``to_hook_plan`` turns this
   plan into a views-only ``HookPlan`` (no declared callbacks) so every actor is a probe that snapshots the
   views when the target pays it. ``invariants`` emits ``invariant_readReentrancy_viewsConsistentOnPayout``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

if __package__:
    from . import hook_reentrancy
else:  # pragma: no cover - exercised only when run as a loose script directory
    import hook_reentrancy  # type: ignore

# State variables an economic view is built on; a write to one of these after a payment is the risk.
ACCOUNTING_VAR = re.compile(
    r"(total|supply|asset|reserve|share|balance|deposit|debt|price|liquidity|stake|collateral|borrow|index)",
    re.I)
TOKEN_MOVE = {"transfer", "safeTransfer", "transferFrom", "safeTransferFrom"}


def _expr_name(node: dict | None) -> str | None:
    if not isinstance(node, dict):
        return None
    nt = node.get("nodeType")
    if nt == "Identifier":
        return node.get("name")
    if nt == "MemberAccess":
        return node.get("memberName")
    if nt == "IndexAccess":
        return _expr_name(node.get("baseExpression"))
    return None


def _is_this_arg(node: dict | None) -> bool:
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") == "FunctionCall" and node.get("kind") == "typeConversion":
        args = node.get("arguments") or []
        return bool(args) and _is_this_arg(args[0])
    return node.get("nodeType") == "Identifier" and node.get("name") in ("this",)


def _lhs_state_write(node: dict, state_names: set[str]) -> bool:
    """True when ``node`` assigns to (or delete/++/-- on) an accounting state variable."""
    nt = node.get("nodeType")
    target = None
    if nt == "Assignment":
        target = node.get("leftHandSide")
    elif nt == "UnaryOperation" and node.get("operator") in ("++", "--", "delete"):
        target = node.get("subExpression")
    if target is None:
        return False
    name = _expr_name(target)
    if not name:
        return False
    return name in state_names or bool(ACCOUNTING_VAR.search(name))


def _classify_payment(node: dict) -> str | None:
    """Return 'native' / 'token' when ``node`` is a payment to someone, else None."""
    if node.get("nodeType") != "FunctionCall":
        return None
    callee = node.get("expression") or {}
    value_option = False
    if callee.get("nodeType") == "FunctionCallOptions":
        names = callee.get("names") or []
        value_option = "value" in names
        callee = callee.get("expression") or {}
    member = callee.get("memberName") if callee.get("nodeType") == "MemberAccess" else None
    args = node.get("arguments") or []
    # Native: .call{value: ...}(...), or address.transfer(amount) / .send(amount) (one argument).
    if value_option:
        return "native"
    if member in ("transfer", "send") and len(args) == 1:
        return "native"
    # Token: transfer(to, amount) / transferFrom(from, to, amount) / safeTransfer* to a non-this recipient.
    if member in TOKEN_MOVE:
        if member in ("transfer", "safeTransfer"):
            recipient = args[0] if len(args) == 2 else (args[1] if len(args) >= 3 else None)
        else:  # transferFrom / safeTransferFrom
            recipient = args[1] if len(args) >= 3 else (args[0] if args else None)
        if recipient is not None and not _is_this_arg(recipient):
            return "token"
    return None


def detect_payout_before_settle_ast(body: dict | None, state_names: set[str] | None = None) -> dict:
    """Per-function: does a payment to the caller come before an accounting state write (source order)?"""
    state_names = state_names or set()
    events: list[tuple[int, str]] = []  # (order, kind) kind in {"native", "token", "settle"}
    counter = 0

    def walk(node) -> None:
        nonlocal counter
        if isinstance(node, list):
            for n in node:
                walk(n)
            return
        if not isinstance(node, dict):
            return
        counter += 1
        here = counter
        kind = _classify_payment(node)
        if kind:
            events.append((here, kind))
        if _lhs_state_write(node, state_names):
            events.append((here, "settle"))
        for k, v in node.items():
            if isinstance(v, (dict, list)) and k != "typeDescriptions":
                walk(v)

    walk(body)
    first_native = next((o for o, k in events if k == "native"), None)
    first_token = next((o for o, k in events if k == "token"), None)
    last_settle = max((o for o, k in events if k == "settle"), default=None)
    native = first_native is not None and last_settle is not None and first_native < last_settle
    token = first_token is not None and last_settle is not None and first_token < last_settle
    return {"native": native, "token": token}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


@dataclass
class ReadReentrancyPlan:
    views: list[tuple[str, str]] = field(default_factory=list)  # (label, calldata) economic views at risk
    sites: list[str] = field(default_factory=list)              # "Contract.function" with the ordering defect
    native: bool = False                                        # a native payment precedes settlement (observable)
    token: bool = False                                         # a token payment precedes settlement (ERC-777 risk)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"views": [v for v, _ in self.views], "sites": self.sites,
                "native": self.native, "token": self.token}


def analyze(target_name: str, functions: list[dict], flows: list[dict], lineage: list[dict],
            settings: dict | None = None) -> ReadReentrancyPlan | None:
    """Return the Preset 08 plan for a target, or None when no payout-before-settle view risk is found."""
    settings = settings or {}
    if settings.get("read_reentrancy", True) is False:
        return None

    state_names = {v["name"] for c in lineage for v in c.get("state_vars", [])}
    native = token = False
    sites: list[str] = []
    for c in lineage:
        for fn in c.get("functions", []):
            d = fn.get("payout_settle") or {}
            if d.get("native") or d.get("token"):
                sites.append(f"{c['name']}.{fn['name']}")
                native = native or bool(d.get("native"))
                token = token or bool(d.get("token"))
    if not native and not token:
        return None

    # Economic views a reader would read during the payment.
    views: dict[str, str] = {}
    state_vars = [v for c in lineage for v in c.get("state_vars", []) if v.get("visibility", "public") == "public"]
    for fn in functions:
        if fn.get("mutability") != "view" or fn.get("visibility") not in ("public", "external"):
            continue
        if not hook_reentrancy.VIEW_NAME.match(fn["name"]) or hook_reentrancy.LOCK_GETTER.match(fn["name"]):
            continue
        ptypes = [p["type"] for p in fn["params"]]
        if not ptypes:
            views.setdefault(fn["name"], f'abi.encodeWithSignature("{fn["name"]}()")')
        elif ptypes == ["uint256"] and hook_reentrancy.UNIT_ARG_VIEWS.match(fn["name"]):
            views.setdefault(f"{fn['name']}(1e18)",
                             f'abi.encodeWithSignature("{fn["name"]}(uint256)", uint256(1e18))')
    for v in state_vars:
        if v["type"].startswith("mapping") or "[" in v["type"] or not hook_reentrancy.VIEW_NAME.match(v["name"]):
            continue
        views.setdefault(v["name"], f'abi.encodeWithSignature("{v["name"]}()")')

    if not views:
        return None  # nothing economic for a reader to misread

    plan = ReadReentrancyPlan(views=sorted(views.items())[:hook_reentrancy.MAX_VIEWS], sites=sorted(set(sites)),
                              native=native, token=token)
    if token and not native:
        plan.notes.append(
            f"Preset 08: {target_name} sends tokens to the caller before it settles accounting; an ERC-777 "
            f"tokensReceived hook could read a half-updated view. Faithfully reproducing that needs the ERC-1820 "
            f"registry, so this is reported, not fuzzed - apply checks-effects-interactions or a read lock.")
    elif token:
        plan.notes.append(
            f"Preset 08: {target_name} also moves tokens to the caller before settling; if that token can call "
            f"back (ERC-777), the same view inconsistency applies.")
    return plan


def to_hook_plan(plan: ReadReentrancyPlan) -> "hook_reentrancy.HookPlan":
    """Reuse the Preset 04 probe to observe the native payment: a views-only plan, no declared callbacks."""
    hp = hook_reentrancy.HookPlan(
        callbacks=[], receivers=["native payment to the caller"], call_sites=list(plan.sites))
    hp.views = list(plan.views)
    hp.read_reentrancy = True
    return hp


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def invariants(target_name: str, plan: ReadReentrancyPlan) -> list[tuple[str, str, str]]:
    if not (plan.native and plan.views):
        return []
    return [(
        "invariant_readReentrancy_viewsConsistentOnPayout",
        f"/// @notice Preset 08: when {target_name} pays an actor in the middle of a flow, the economic views it\n"
        "    ///         exposes read either the pre-flow or the post-flow state, never a half-settled one. A reader\n"
        "    ///         (a lending market, an AMM, an oracle) that priced off the interim value would be wrong.\n"
        f"    /// @dev Views watched: {', '.join(v for v, _ in plan.views)}. Defect sites: {', '.join(plan.sites)}.\n"
        "    ///      The fix is checks-effects-interactions (settle before paying) or a read lock the views honour.",
        '        assertEq(handler.hookInconsistentReads(), 0, "an economic view read a half-settled state while the contract was paying the caller mid-flow (read-only reentrancy); settle before paying out");',
    )]
