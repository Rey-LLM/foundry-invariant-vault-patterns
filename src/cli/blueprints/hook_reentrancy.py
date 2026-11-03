"""Preset 04: hook-based read-reentrancy (Uniswap v4 style hook architectures).

A contract that calls out to an external hook in the middle of a state transition (``beforeSwap`` /
``afterSwap`` / ``afterAddLiquidity`` hooks, ``unlockCallback`` / ``lockAcquired`` callbacks on
``msg.sender``, ``*Callback`` and ``onFlashLoan`` calls) hands control to code it does not own while
its own state may be half-updated. Two things can go wrong:

* **read-only reentrancy**: the hook (or any protocol it calls) reads the contract's views
  (``totalAssets``, ``totalSupply``, prices, reserves ...) and sees a state that is neither the state
  before the call nor the state after it, e.g. assets already sent but shares not yet burned;
* **state-changing reentrancy**: the hook calls back into a flow that is meant to be locked.

This module does three jobs for the parser and the injector:

1. ``detect_callbacks_ast`` finds hook call sites in solc AST function bodies (``FunctionCall`` on a
   ``MemberAccess``, through ``IHooks(h).x`` type conversions and ``{gas: ...}`` call options).
2. ``analyze`` decides whether a target gets the preset and how to wire it: which views to snapshot,
   which lock getter to check, which flows claim to be ``nonReentrant``, how the hook address reaches
   the contract (constructor / initializer parameter, setter, or ``msg.sender`` callbacks).
3. ``render_probe`` / ``render_handler_helpers`` / ``invariants`` emit the Solidity: a
   ``<Contract>HookProbe`` that is both every fuzz actor and the registered hook. While a handler
   flow is running, each callback that reaches a probe snapshots the target's views, checks that the
   reentrancy lock reads as engaged, and tries to re-enter the running flow when it is ``nonReentrant``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

# Uniswap v4 IHooks surface.
V4_HOOKS = frozenset({
    "beforeInitialize", "afterInitialize",
    "beforeAddLiquidity", "afterAddLiquidity",
    "beforeRemoveLiquidity", "afterRemoveLiquidity",
    "beforeSwap", "afterSwap",
    "beforeDonate", "afterDonate",
})
# Callback names that hand control to the caller or a registered contract, whatever the receiver.
CALLBACK_NAME = re.compile(r"^(unlockCallback|lockAcquired|onFlashLoan|[a-z]\w*Callback)$")
# before*/after* on a receiver that looks like a hook (``hooks.afterDeposit``, ``IVaultHooks(h).beforeX``).
GENERIC_HOOK_NAME = re.compile(r"^(before|after)[A-Z]\w*$")
HOOKISH = re.compile(r"hook|callback", re.I)
NOT_RECEIVERS = {"super", "this", "abi", "msg", "block", "tx", "type", "bytes", "string"}


def is_callback_name(name: str) -> bool:
    """True for hook / callback entry points (``unlockCallback``, ``beforeSwap``, ``onFlashLoan`` ...)."""
    return name in V4_HOOKS or bool(CALLBACK_NAME.match(name))


def classify_call(name: str, receiver: str | None, cast: str | None = None) -> dict | None:
    """Return a callback record when ``receiver.name(...)`` hands control to an external hook."""
    receiver = re.sub(r"\s+", "", receiver or "")
    if not receiver or receiver.split(".")[0] in NOT_RECEIVERS and receiver != "msg.sender":
        return None
    hookish = bool(HOOKISH.search(receiver) or HOOKISH.search(cast or ""))
    if name in V4_HOOKS or CALLBACK_NAME.match(name) or (hookish and GENERIC_HOOK_NAME.match(name)):
        return {"name": name, "receiver": receiver, "via": cast}
    return None


def _dedupe(found: list[dict]) -> list[dict]:
    out, seen = [], set()
    for cb in found:
        key = (cb["name"], cb["receiver"], cb.get("via"))
        if key not in seen:
            seen.add(key)
            out.append(cb)
    return out


def _expr_text(node: dict | None) -> str | None:
    if not isinstance(node, dict):
        return None
    nt = node.get("nodeType")
    if nt == "Identifier":
        return node.get("name")
    if nt == "MemberAccess":
        base = _expr_text(node.get("expression"))
        return f"{base}.{node.get('memberName')}" if base else None
    return None


def detect_callbacks_ast(body: dict | None) -> list[dict]:
    """Hook call sites in a solc AST function body."""
    found: list[dict] = []
    stack = [body] if body else []
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        if node.get("nodeType") == "FunctionCall":
            callee = node.get("expression") or {}
            if callee.get("nodeType") == "FunctionCallOptions":
                callee = callee.get("expression") or {}
            if callee.get("nodeType") == "MemberAccess":
                base = callee.get("expression") or {}
                cast = receiver = None
                if base.get("nodeType") == "FunctionCall" and base.get("kind") == "typeConversion":
                    cast = _expr_text(base.get("expression"))
                    args = base.get("arguments") or []
                    receiver = _expr_text(args[0]) if args else None
                else:
                    receiver = _expr_text(base)
                cb = classify_call(callee.get("memberName", ""), receiver, cast)
                if cb:
                    found.append(cb)
        stack.extend(v for k, v in node.items() if isinstance(v, (dict, list)) and k != "typeDescriptions")
    return _dedupe(found)


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

VIEW_NAME = re.compile(
    r"^(total[A-Z]\w*|\w*[Pp]rice\w*|\w*[Rr]ate|\w*[Pp]erShare|getReserves?|\w*[Rr]eserves?\d*|\w*[Ss]upply"
    r"|liquidity|slot0|sqrtPrice\w*|\w*Index|convertTo(Assets|Shares)|preview(Deposit|Mint|Withdraw|Redeem))$"
)
UNIT_ARG_VIEWS = re.compile(r"^(convertTo(Assets|Shares)|preview(Deposit|Mint|Withdraw|Redeem))$")
LOCK_GETTER = re.compile(r"^(locked|isLocked|reentrancyGuardEntered|entered|isEntered)$")
NONREENTRANT_MODIFIER = re.compile(r"^(nonReentrant\w*|lock|noReentrancy|noReentrant|reentrancyGuard|noReenter|mutex)$")
HOOK_PARAM_TYPE = re.compile(r"^I?\w*(Hook|Hooks|Callback|Callbacks)\w*$")
HOOK_PARAM_NAME = re.compile(r"hook|callback", re.I)
HOOK_SETTER = re.compile(r"^(set|update|register|change)\w*(Hook|Hooks|Callback)\w*$")
MAX_VIEWS = 12
DYNAMIC = re.compile(r"^(bytes|string)$|\[\d*\]$")
ELEMENTARY = re.compile(r"^(u?int\d*|address|bool|bytes([1-9]|[12]\d|3[0-2]))$")


@dataclass
class HookPlan:
    callbacks: list[str]                       # callback names the target invokes
    receivers: list[str]                       # how it reaches the hook ("hooks", "msg.sender", ...)
    call_sites: list[str]                      # "Contract.function" that contain the call
    views: list[tuple[str, str]] = field(default_factory=list)   # (label, calldata expression)
    lock_getter: str | None = None
    guarded_flows: set[str] = field(default_factory=set)         # nonReentrant flow signatures
    setter: dict | None = None
    returns: list[dict] = field(default_factory=list)            # dynamic-return dispatch entries
    imports: list[tuple[str, str]] = field(default_factory=list)  # (symbol, file) for selectors
    notes: list[str] = field(default_factory=list)
    read_reentrancy: bool = False  # Preset 08 reuses this probe to watch a native payout (no declared hook)

    @property
    def msg_sender(self) -> bool:
        return "msg.sender" in self.receivers

    def summary(self) -> dict:
        return {
            "callbacks": self.callbacks,
            "receivers": self.receivers,
            "call_sites": self.call_sites,
            "views": [v for v, _ in self.views],
            "lock_getter": self.lock_getter,
            "nonreentrant_flows": sorted(self.guarded_flows),
            "setter": self.setter["signature"] if self.setter else None,
        }


def is_hook_param(p: dict) -> bool:
    t, name = p["type"], p["name"]
    if HOOK_PARAM_TYPE.match(t) and not ELEMENTARY.match(t):
        return True
    return t == "address" and bool(HOOK_PARAM_NAME.search(name))


def _abi_type(t: str) -> str:
    m = re.match(r"^(.+?)((\[\d*\])+)$", t)
    if m:
        return _abi_type(m.group(1)) + m.group(2)
    return t if ELEMENTARY.match(t) or t in ("string", "bytes") else "address"


def _zero(t: str, first: bool) -> str:
    if t == "bytes4" and first:
        return "msg.sig"
    if t == "bytes":
        return 'bytes("")'
    if t == "string":
        return 'string("")'
    m = re.match(r"^(.+)\[\d*\]$", t)
    if m:
        inner = m.group(1)
        return f"new {inner if ELEMENTARY.match(inner) else 'uint256'}[](0)"
    if re.match(r"^u?int\d*$", t) or re.match(r"^bytes\d+$", t):
        return f"{t}(0)"
    if t == "bool":
        return "false"
    if t == "address":
        return "address(0)"
    return "uint256(0)"  # user-defined value types (BeforeSwapDelta, BalanceDelta, ...) are one word


def analyze(target_name: str, functions: list[dict], flows: list[dict], lineage: list[dict],
            all_contracts: list[dict]) -> HookPlan | None:
    """Return the Preset 04 plan for a target, or None when it never calls out to a hook."""
    callbacks: list[dict] = []
    sites: list[str] = []
    for c in lineage:
        for fn in c.get("functions", []) + ([c["constructor"]] if c.get("constructor") else []):
            cbs = fn.get("callbacks") or []
            if cbs:
                callbacks.extend(cbs)
                sites.append(f"{c['name']}.{fn['name']}")
    if not callbacks:
        return None
    hp = HookPlan(
        callbacks=sorted({cb["name"] for cb in callbacks}),
        receivers=sorted({cb["receiver"] for cb in callbacks}),
        call_sites=sorted(set(sites)),
    )

    state_vars = []
    for c in lineage:
        state_vars.extend(v for v in c.get("state_vars", []) if v.get("visibility", "public") == "public")

    # Views a third party would read mid-callback.
    views: dict[str, str] = {}
    for fn in functions:
        if fn.get("mutability") != "view" or fn.get("visibility") not in ("public", "external"):
            continue
        if not VIEW_NAME.match(fn["name"]) or LOCK_GETTER.match(fn["name"]):
            continue
        ptypes = [p["type"] for p in fn["params"]]
        if not ptypes:
            views.setdefault(fn["name"], f'abi.encodeWithSignature("{fn["name"]}()")')
        elif ptypes == ["uint256"] and UNIT_ARG_VIEWS.match(fn["name"]):
            views.setdefault(f"{fn['name']}(1e18)", f'abi.encodeWithSignature("{fn["name"]}(uint256)", uint256(1e18))')
    for v in state_vars:
        if v["type"].startswith("mapping") or "[" in v["type"] or not VIEW_NAME.match(v["name"]):
            continue
        views.setdefault(v["name"], f'abi.encodeWithSignature("{v["name"]}()")')
    hp.views = sorted(views.items())[:MAX_VIEWS]

    # Reentrancy lock getter: expected to read `true` while the target is calling out.
    for fn in functions:
        if (LOCK_GETTER.match(fn["name"]) and not fn["params"] and fn.get("mutability") == "view"
                and [r["type"] for r in fn.get("returns", [])] == ["bool"]):
            hp.lock_getter = fn["name"]
            break
    else:
        hp.lock_getter = next((v["name"] for v in state_vars if LOCK_GETTER.match(v["name"]) and v["type"] == "bool"), None)

    hp.guarded_flows = {f["signature"] for f in flows
                        if any(NONREENTRANT_MODIFIER.match(m) for m in f.get("modifiers", []))}
    hp.setter = next((f for f in functions if HOOK_SETTER.match(f["name"]) and len(f["params"]) == 1
                      and (_abi_type(f["params"][0]["type"]) == "address")), None)

    # Callbacks whose return value is dynamic (`unlockCallback returns (bytes)`) need their own encoding.
    for name in hp.callbacks:
        decl = None
        for c in all_contracts:
            same = [f for f in c.get("functions", []) if f["name"] == name and f.get("kind") == "function"]
            if same and (decl is None or c["kind"] == "interface"):
                decl = (c, same)
                if c["kind"] == "interface":
                    break
        if decl is None:
            continue
        c, same = decl
        rtypes = [r["type"] for r in same[0].get("returns", [])]
        if not any(DYNAMIC.search(t) for t in rtypes):
            continue
        if len(same) > 1:
            hp.notes.append(f"{c['name']}.{name} is overloaded; the probe answers it with the default static encoding")
            continue
        hp.imports.append((c["name"], c["file"]))
        hp.returns.append({"selector": f"{c['name']}.{name}.selector",
                           "encode": "abi.encode(" + ", ".join(_zero(t, i == 0) for i, t in enumerate(rtypes)) + ")",
                           "callback": name})
    return hp


def wiring_notes(hp: HookPlan, hook_params_used: int, flows: list[dict]) -> list[str]:
    """Explain receivers the generated setUp could not point at the probe."""
    if hp.read_reentrancy or hp.msg_sender or hook_params_used or hp.setter:
        return []  # Preset 08: the actor is the payee, so no hook wiring is needed
    if any(p["type"] == "address" and HOOK_PARAM_NAME.search(p["name"]) for f in flows for p in f["params"]):
        return []
    return [f"hook receiver(s) {', '.join(hp.receivers)} could not be pointed at the probe; pass "
            "`hookProbes[0]` through [contracts.<Name>] constructor_args or setup so callbacks reach it"]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

COUNTERS = (
    ("hookCalls", "callbacks observed while a handler flow was running"),
    ("guardedReads", "mid-callback snapshots in which a view reverted (a read guard is in place)"),
    ("inconsistentReads", "mid-callback snapshots equal to neither the pre-call nor the post-call state"),
    ("lockNotEngaged", "callbacks during which the reentrancy lock getter read `false`"),
    ("reentryAttempts", "re-entries into a nonReentrant flow tried from inside a callback"),
    ("unguardedReentries", "re-entries that succeeded"),
)


def probe_name(target_name: str) -> str:
    return f"{target_name}HookProbe"


def render_probe(target_name: str, hp: HookPlan) -> str:
    name = probe_name(target_name)
    snaps = []
    for i, (label, call) in enumerate(hp.views):
        snaps.append(f"        // {label}\n"
                     f"        (ok, ret) = target.staticcall({call});\n"
                     f"        if (!ok) revertMask |= 1 << {i};\n"
                     "        h = keccak256(abi.encode(h, ok, ret));")
    snapshot_body = ("        bool ok;\n        bytes memory ret;\n" + "\n".join(snaps)) if snaps else \
        "        // No price / accounting views found: nothing to compare."
    lock = ""
    if hp.lock_getter:
        lock = f"""
        (bool lockOk, bytes memory lockRet) = target.staticcall(abi.encodeWithSignature("{hp.lock_getter}()"));
        if (lockOk && lockRet.length >= 32 && !abi.decode(lockRet, (bool))) lockNotEngaged++;"""
    dispatch = "".join(f"\n        if (msg.sig == {r['selector']}) return {r['encode']};" for r in hp.returns)
    counters = "\n".join(f"    /// {doc}.\n    uint256 public {n};" for n, doc in COUNTERS)
    return f"""
/// @title {name}
/// @notice Preset 04 (hook read-reentrancy). Every fuzz actor is a probe, and so is the hook
///         {target_name} is wired to. When {target_name} calls out mid-execution
///         ({', '.join(hp.callbacks)}, or a native ETH transfer), the probe snapshots its views, checks
///         the reentrancy lock and tries to re-enter the nonReentrant flow that is running.
contract {name} {{
    address public target;
    bool public active;
    bool internal reentering;
    bytes internal reentryData;
    bytes32 internal preHash;
    uint256 internal preMask;
    bytes32[] internal midHashes;
    uint256[] internal midMasks;

{counters}

    function arm(address target_) external {{
        require(target == address(0), "{name}: already armed");
        target = target_;
    }}

    /// @notice Hash of every watched view of the target, plus a bit per view that reverted.
    function snapshot() public view returns (bytes32 h, uint256 revertMask) {{
{snapshot_body}
    }}

    function begin(bytes32 preHash_, uint256 preMask_, bytes calldata reentry) external {{
        active = true;
        preHash = preHash_;
        preMask = preMask_;
        reentryData = reentry;
        delete midHashes;
        delete midMasks;
    }}

    /// @notice Compares every mid-callback snapshot with the states before and after the flow.
    ///         A reverted flow rolls back the probe's writes too, so only completed flows are judged.
    function end(bool succeeded, bytes32 postHash, uint256 postMask) external {{
        active = false;
        if (succeeded) {{
            uint256 stable = preMask & postMask;
            for (uint256 i = 0; i < midHashes.length; i++) {{
                if (midMasks[i] & ~stable != 0) guardedReads++;
                else if (midHashes[i] != preHash && midHashes[i] != postHash) inconsistentReads++;
            }}
        }}
        delete midHashes;
        delete midMasks;
    }}

    /// @dev Any hook or callback: observe, then answer with the selector followed by zero words, which
    ///      decodes as `bytes4` and as (`bytes4`, deltas, fees) tuples such as v4's beforeSwap.
    fallback(bytes calldata) external payable returns (bytes memory) {{
        _observe();{dispatch}
        return abi.encode(msg.sig, uint256(0), uint256(0), uint256(0), uint256(0));
    }}

    receive() external payable {{
        if (gasleft() > 100_000) _observe();
    }}

    function _observe() internal {{
        if (!active || reentering || msg.sender != target) return;
        hookCalls++;
        (bytes32 h, uint256 m) = snapshot();
        midHashes.push(h);
        midMasks.push(m);{lock}
        if (reentryData.length != 0) {{
            reentering = true;
            reentryAttempts++;
            (bool reentered, ) = target.call(reentryData);
            if (reentered) unguardedReentries++;
            reentering = false;
        }}
    }}
}}
"""


def render_handler_helpers(target_name: str) -> str:
    name = probe_name(target_name)
    getters = "\n".join(
        f"""
    function hook{n[0].upper()}{n[1:]}() external view returns (uint256 total) {{
        for (uint256 i = 0; i < probes.length; i++) total += probes[i].{n}();
    }}""" for n, _ in COUNTERS)
    return f"""
    /// @dev Preset 04: arms every probe with the pre-call snapshot and the re-entry calldata.
    function _hookBegin(bytes memory reentry) internal {{
        (bytes32 h, uint256 m) = probes[0].snapshot();
        for (uint256 i = 0; i < probes.length; i++) probes[i].begin(h, m, reentry);
    }}

    function _hookEnd(bool succeeded) internal {{
        bytes32 h;
        uint256 m;
        if (succeeded) (h, m) = probes[0].snapshot();
        for (uint256 i = 0; i < probes.length; i++) probes[i].end(succeeded, h, m);
    }}
{getters}
"""


def invariants(target_name: str, hp: HookPlan) -> list[tuple[str, str, str]]:
    out = []
    if hp.read_reentrancy:
        return out  # Preset 08 owns the invariant (invariant_readReentrancy_viewsConsistentOnPayout)
    if hp.views:
        out.append((
            "invariant_hook_readConsistency",
            f"/// @notice Preset 04: views read inside a hook callback show {target_name}'s state either before\n"
            "    ///         or after the running flow, never a half-updated one (read-only reentrancy).\n"
            f"    /// @dev Watched: {', '.join(v for v, _ in hp.views)}. Relax if a partial state is intended.",
            '        assertEq(handler.hookInconsistentReads(), 0, "read-only reentrancy: a view read inside a hook callback saw a half-updated state");',
        ))
    if hp.lock_getter:
        out.append((
            "invariant_hook_lockEngagedDuringCallback",
            f"/// @notice Preset 04: {hp.lock_getter}() reads true whenever {target_name} is calling out to a hook.",
            f'        assertEq(handler.hookLockNotEngaged(), 0, "{hp.lock_getter}() was false while a hook callback was running");',
        ))
    if hp.guarded_flows:
        out.append((
            "invariant_hook_guardedFlowsNotReentered",
            "/// @notice Preset 04: a nonReentrant flow cannot be re-entered from inside a hook callback.\n"
            f"    /// @dev Guarded: {', '.join(sorted(hp.guarded_flows))}.",
            '        assertEq(handler.hookUnguardedReentries(), 0, "a nonReentrant flow was re-entered from a hook callback");',
        ))
    return out
