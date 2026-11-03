"""Preset 06: cross-protocol flash-loan arbitrage and price squeezing.

A protocol that reads a price (or a value, a rate, an amount-out) from a source an attacker can move
inside one transaction, and then lets value flow at that price, can be drained with a flash loan: borrow
a large amount, squeeze the source, transact at the wrong price, unwind, repay, keep the difference. The
two sources that move within a transaction are:

* **the contract's own token balance**: ``asset.balanceOf(address(this))`` or ``address(this).balance``
  used to price a redemption or value a position. A direct transfer (donation) changes it with no deposit;
* **a spot read on another contract**: an AMM's ``getReserves`` / ``slot0`` / ``getAmountOut``, an oracle's
  ``latestAnswer`` / ``consult`` that follows spot, read in the middle of a value flow.

This preset is **report-only**. It flags the surface for the developer and explains the squeeze, but it
generates no pass/fail invariant. The reason is that the obvious invariant - "a bare donation never moves a
priced view" - is a false positive: a donation moving a vault's share price up is normal, correct ERC-4626
behaviour, not a bug (the donation is shared among existing holders). What makes it a *vulnerability* is
whether value then flows at the squeezed price within the same transaction, which depends on the economic
design, not on a property a fuzzer can decide. So FoundryGuard surfaces the finding for a human to judge
rather than failing a build on a legitimate design.

To keep the finding precise (and not fire on every contract that happens to read its own balance for a
read-only surplus view), detection is transitive: a contract is flagged only when a per-unit price view or a
value flow actually reaches a self-balance read through its call graph - ``convertToAssets`` -> ``_backing``
-> ``balanceOf(address(this))`` counts; a standalone ``skimmable()`` that reads the balance but prices
nothing does not.

This module does three jobs for the parser and the injector:

1. ``detect_self_balance_pricing_ast`` finds ``balanceOf(address(this))`` / ``address(this).balance`` reads
   in a solc AST function body (the self-balance pricing signal), and ``detect_internal_calls_ast`` lists the
   same-contract functions a body calls, so the two together give a call graph.
2. ``reached_balance_readers`` walks that call graph to decide whether an entry point reaches a self-balance
   read.
3. ``analyze`` decides whether a target gets the preset (and what the report says); there is no rendering,
   because the preset emits no Solidity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

# Spot reads on another contract that an attacker can move within a transaction.
SPOT_CALL = re.compile(
    r"^(getReserves?|slot0|observe|consult|getAmountO?ut|getAmountsOut|getQuote|quote|price\d*|getPrice"
    r"|latestAnswer|latestRoundData|currentPrice|spotPrice|getSpot|peek|read)$"
)
# Per-unit price / conversion views: a position in the protocol is valued through one of these.
PRICE_VIEW = re.compile(
    r"^(convertTo(Assets|Shares)|preview(Deposit|Mint|Withdraw|Redeem)|pricePerShare|getPricePerFullShare"
    r"|sharePrice|exchangeRate|getExchangeRate|assetsPerShare|pps)$"
)


def _is_this(node: dict | None) -> bool:
    """True for ``address(this)`` or ``this``."""
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") == "FunctionCall" and node.get("kind") == "typeConversion":
        args = node.get("arguments") or []
        return bool(args) and _is_this(args[0])
    return node.get("nodeType") == "Identifier" and node.get("name") == "this"


def detect_self_balance_pricing_ast(body: dict | None) -> bool:
    """True when a function body reads its own token balance or ETH balance (a spot price source)."""
    stack = [body] if body else []
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        if node.get("nodeType") == "MemberAccess":
            member = node.get("memberName")
            # address(this).balance
            if member == "balance" and _is_this(node.get("expression")):
                return True
            # x.balanceOf(address(this)) -> MemberAccess balanceOf, called with this
        if node.get("nodeType") == "FunctionCall":
            callee = node.get("expression") or {}
            if callee.get("nodeType") == "MemberAccess" and callee.get("memberName") == "balanceOf":
                for a in node.get("arguments") or []:
                    if _is_this(a):
                        return True
        stack.extend(v for k, v in node.items() if isinstance(v, (dict, list)) and k != "typeDescriptions")
    return False


def detect_internal_calls_ast(body: dict | None) -> list[str]:
    """Names of same-contract functions a body calls directly, e.g. ``_backing()`` or ``convertToAssets(x)``.

    These are the ``FunctionCall`` nodes whose callee is a plain ``Identifier``. External calls
    (``token.foo()``) are ``MemberAccess`` and are left out, as are type conversions (``address(x)``) and
    struct constructors. Builtins like ``require`` are harmless noise - they never resolve in the call graph.
    """
    out: list[str] = []
    stack = [body] if body else []
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        if node.get("nodeType") == "FunctionCall" and node.get("kind") == "functionCall":
            callee = node.get("expression") or {}
            if callee.get("nodeType") == "Identifier" and callee.get("name"):
                out.append(callee["name"])
        stack.extend(v for k, v in node.items() if isinstance(v, (dict, list)) and k != "typeDescriptions")
    seen: set[str] = set()
    ordered: list[str] = []
    for n in out:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


def reached_balance_readers(entry: str, fnmap: dict[str, dict]) -> set[str]:
    """Self-balance-reading functions reachable from ``entry`` through the call graph (``entry`` included).

    ``fnmap`` maps a function name to its parsed dict; each needs ``reads_self_balance`` and
    ``internal_calls``. Returns the set of reached function names that read a balance (empty if none), so a
    non-empty result means the entry point prices off a balance an attacker can move.
    """
    out: set[str] = set()
    stack = [entry]
    seen: set[str] = set()
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        fn = fnmap.get(name)
        if not fn:
            continue
        if fn.get("reads_self_balance"):
            out.add(name)
        stack.extend(fn.get("internal_calls") or [])
    return out


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


@dataclass
class FlashLoanPlan:
    sources: list[str] = field(default_factory=list)      # human-readable manipulable price sources
    priced_views: list[str] = field(default_factory=list)  # per-unit price views read off a manipulable source
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"sources": self.sources, "priced_views": self.priced_views}


def analyze(target_name: str, functions: list[dict], flows: list[dict], lineage: list[dict],
            links: list[dict], settings: dict | None = None) -> FlashLoanPlan | None:
    """Return the Preset 06 report for a target, or None when no priced path reaches a manipulable source."""
    settings = settings or {}
    if settings.get("flashloan", True) is False:
        return None
    flow_sigs = {f["signature"] for f in flows}

    # Call graph over the whole inheritance chain: a priced view may reach a self-balance read through an
    # internal helper (convertToAssets -> _backing -> balanceOf(address(this))). First name wins (the most
    # derived override), matching how Solidity resolves the call.
    fnmap: dict[str, dict] = {}
    for c in lineage:
        for fn in c.get("functions", []):
            fnmap.setdefault(fn["name"], fn)
    for fn in functions:
        fnmap.setdefault(fn["name"], fn)

    balance_sites: set[str] = set()

    # Price source 1: a public/external per-unit price view whose quote is read (transitively) off the
    # contract's own balance. A bare donation moves that balance, so it moves the quote.
    priced_views: set[str] = set()
    for fn in functions:
        if fn.get("mutability") != "view" or fn.get("visibility") not in ("public", "external"):
            continue
        if not PRICE_VIEW.match(fn["name"]):
            continue
        reached = reached_balance_readers(fn["name"], fnmap)
        if reached:
            balance_sites |= reached
            priced_views.add(fn["name"])

    # Price source 1b: a value flow (deposit / withdraw / redeem ...) that prices off the balance inline,
    # even without a named view - the redemption amount itself is squeezable.
    for f in flows:
        balance_sites |= reached_balance_readers(f["signature"].split("(")[0], fnmap)

    # Price source 2: a spot read on a linked contract, used inside a value flow (not just a keeper call).
    spot_links = []
    for link in links or []:
        spot = sorted({c for c in link.get("calls", []) if SPOT_CALL.match(c)})
        if spot and set(link.get("used_in", [])) & flow_sigs:
            spot_links.append(f"{link['var']}.{'/'.join(spot)}")

    if not balance_sites and not spot_links:
        return None

    sources: list[str] = []
    if balance_sites:
        sources.append("self-balance read (" + ", ".join(sorted(f"{target_name}.{n}" for n in balance_sites)) + ")")
    sources.extend("spot read " + s for s in spot_links)

    plan = FlashLoanPlan(sources=sources, priced_views=sorted(priced_views))
    detail = f" Priced views read off it: {', '.join(plan.priced_views)}." if plan.priced_views else ""
    plan.notes.append(
        f"Preset 06: {target_name} derives value from a price source an attacker can move inside one "
        f"transaction ({'; '.join(sources)}).{detail} A bare donation (a direct transfer, no deposit) or a "
        f"flash loan can push that source and then transact against the wrong price. Reported for review; "
        f"FoundryGuard generates no pass/fail invariant here, because a donation moving a vault's share price "
        f"is normal behaviour rather than a bug - judge by hand whether value flows at the squeezed price, and "
        f"prefer a TWAP or internal accounting that ignores unsolicited transfers.")
    return plan
