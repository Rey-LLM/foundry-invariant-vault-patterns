"""Preset 05: EIP-1153 transient storage left set between calls.

EIP-1153 clears transient storage when the transaction ends, not when a call returns. A check made
after the transaction therefore always passes and proves nothing. The real bug is a slot that one call
leaves set while the transaction goes on: the next call in the same transaction (a multicall, a router,
a callback chain, a batched bundle) reads that leftover value. A lock that is never released bricks
every later call; a cached amount or a "flow in progress" flag that is never cleared is read as if it
belonged to the new call.

This module does three jobs for the parser and the injector:

1. ``scan`` walks solc AST function and modifier bodies for ``InlineAssembly`` blocks and, inside the
   Yul tree, for ``tstore`` / ``tload`` calls (``YulFunctionCall`` nodes). The slot argument is
   resolved when it is a literal, a Solidity constant (through the block's ``externalReferences``), a
   ``let`` of either, or simple arithmetic on those. Computed slots (``add(BASE, caller())``,
   ``keccak256`` of a key) are recorded as dynamic.
2. ``analyze`` collects the slots a target writes across its whole C3 lineage.
3. ``render_harness`` / ``render_handler_helpers`` / ``invariants`` emit the Solidity: a
   ``<Contract>TransientHarness`` that inherits the target and adds one view reading its own transient
   storage, a handler check that runs after every successful call, a ``transientSequence`` action that
   makes several calls inside one transaction, and ``invariant_transient_slotsClearedBetweenCalls``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

WORD = 1 << 256
MASK = WORD - 1
TRANSIENT_OPS = ("tstore", "tload")
RATIONAL = re.compile(r"^t_rational_(\d+)_by_1$")
HARNESS_READER = "foundryGuardTload"

# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #


def slot_hex(value: int) -> str:
    return "0x" + format(value & MASK, "064x")


def parse_number(text: str) -> int | None:
    """A Solidity / Yul number literal (hex, decimal, ``1e18``, ``1_000``) as an int."""
    t = (text or "").replace("_", "").strip()
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if re.fullmatch(r"\d+", t):
            return int(t)
        m = re.fullmatch(r"(\d+)(?:\.(\d+))?e(\d+)", t, re.I)
        if m:
            whole, frac, exp = m.group(1), m.group(2) or "", int(m.group(3))
            if len(frac) > exp:
                return None
            return int(whole + frac) * 10 ** (exp - len(frac))
    except ValueError:
        return None
    return None


def constant_value(decl: dict | None, lookup: Callable[[int], dict | None], _depth: int = 0) -> int | None:
    """Value of a Solidity ``constant`` (the only kind inline assembly may reference)."""
    if not isinstance(decl, dict) or not decl.get("constant") or _depth > 8:
        return None
    value = decl.get("value")
    if not isinstance(value, dict):
        return None
    # solc folds the value into the rational type (``t_rational_170_by_1``), which also covers
    # sub-denominations such as ``1 ether`` and constants defined through other constants.
    m = RATIONAL.match((value.get("typeDescriptions") or {}).get("typeIdentifier") or "")
    if m:
        return int(m.group(1))
    if value.get("nodeType") == "Literal" and value.get("kind") == "number":
        return parse_number(value.get("value") or "")
    if value.get("nodeType") == "Identifier" and value.get("referencedDeclaration") is not None:
        return constant_value(lookup(value["referencedDeclaration"]), lookup, _depth + 1)
    return None


_FOLD: dict[str, Callable[..., int]] = {
    "add": lambda a, b: (a + b) & MASK,
    "sub": lambda a, b: (a - b) & MASK,
    "mul": lambda a, b: (a * b) & MASK,
    "and": lambda a, b: a & b,
    "or": lambda a, b: a | b,
    "xor": lambda a, b: a ^ b,
    "shl": lambda s, v: (v << s) & MASK if s < 256 else 0,
    "shr": lambda s, v: v >> s if s < 256 else 0,
    "not": lambda a: (~a) & MASK,
}


@dataclass
class _Scope:
    refs: dict[str, dict]                       # Yul identifier src -> externalReferences entry
    resolve: Callable[[int], int | None]        # Solidity declaration id -> constant value
    env: dict[str, int | None] = field(default_factory=dict)  # Yul locals with a known value


def yul_text(e: dict | None) -> str:
    if not isinstance(e, dict):
        return "?"
    nt = e.get("nodeType")
    if nt == "YulLiteral":
        return str(e.get("value", e.get("hexValue", "?")))
    if nt == "YulIdentifier":
        return e.get("name", "?")
    if nt == "YulFunctionCall":
        args = ", ".join(yul_text(a) for a in e.get("arguments") or [])
        return f"{(e.get('functionName') or {}).get('name', '?')}({args})"
    return "?"


def _eval(e: dict | None, scope: _Scope) -> int | None:
    if not isinstance(e, dict):
        return None
    nt = e.get("nodeType")
    if nt == "YulLiteral":
        if e.get("kind") == "bool":
            return 1 if e.get("value") == "true" else 0
        if e.get("kind") == "number":
            return parse_number(str(e.get("value", "")))
        return None
    if nt == "YulIdentifier":
        name = e.get("name", "")
        if name in scope.env:
            return scope.env[name]
        ref = scope.refs.get(e.get("src", ""))
        if ref is None or ref.get("isSlot") or ref.get("isOffset") or ref.get("suffix"):
            return None
        return scope.resolve(ref.get("declaration"))
    if nt == "YulFunctionCall":
        fn = _FOLD.get((e.get("functionName") or {}).get("name", ""))
        args = [_eval(a, scope) for a in e.get("arguments") or []]
        if fn is None or any(a is None for a in args):
            return None
        try:
            return fn(*args)
        except TypeError:
            return None
    return None


def _yul_walk(node, scope: _Scope, found: list[dict], site: str, line: Callable[[str], int]) -> None:
    """Walk Yul in statement order, tracking ``let`` constants, and record every tstore / tload."""
    if isinstance(node, list):
        for n in node:
            _yul_walk(n, scope, found, site, line)
        return
    if not isinstance(node, dict):
        return
    nt = node.get("nodeType")
    if nt == "YulFunctionCall":
        for a in node.get("arguments") or []:
            _yul_walk(a, scope, found, site, line)
        op = (node.get("functionName") or {}).get("name")
        if op in TRANSIENT_OPS:
            args = node.get("arguments") or []
            value = _eval(args[0], scope) if args else None
            found.append({"op": op, "slot": slot_hex(value) if value is not None else None,
                          "expr": yul_text(args[0]) if args else "?", "site": site,
                          "line": line(node.get("src", ""))})
        return
    if nt == "YulVariableDeclaration":
        _yul_walk(node.get("value"), scope, found, site, line)
        names = [v.get("name") for v in node.get("variables") or []]
        value = _eval(node.get("value"), scope) if len(names) == 1 else None
        for n in names:
            scope.env[n] = value
        return
    if nt == "YulAssignment":
        _yul_walk(node.get("value"), scope, found, site, line)
        names = [v.get("name") for v in node.get("variableNames") or []]
        value = _eval(node.get("value"), scope) if len(names) == 1 else None
        for n in names:
            scope.env[n] = value
        return
    if nt == "YulFunctionDefinition":
        inner = _Scope(scope.refs, scope.resolve)  # parameters are unknown inside a Yul function
        _yul_walk(node.get("body"), inner, found, site, line)
        return
    if nt in ("YulIf", "YulSwitch", "YulForLoop"):
        # Branches and loops may or may not run: walk them on a copy, then forget what they reassign.
        before = dict(scope.env)
        branch = _Scope(scope.refs, scope.resolve, dict(scope.env))
        for key in ("condition", "expression", "pre", "post", "body", "cases"):
            _yul_walk(node.get(key), branch, found, site, line)
        for n in before:
            if branch.env.get(n) != before[n]:
                scope.env[n] = None
        return
    if nt == "YulBlock":
        inner = _Scope(scope.refs, scope.resolve, dict(scope.env))
        _yul_walk(node.get("statements"), inner, found, site, line)
        for n in scope.env:
            if inner.env.get(n) != scope.env[n]:
                scope.env[n] = inner.env.get(n)
        return
    if nt == "YulCase":
        _yul_walk(node.get("body"), scope, found, site, line)
        return
    for k, v in node.items():
        if isinstance(v, (dict, list)) and k != "typeDescriptions":
            _yul_walk(v, scope, found, site, line)


def scan(body: dict | None, resolve: Callable[[int], int | None], site: str,
         line: Callable[[str], int] = lambda src: 0) -> list[dict]:
    """Every tstore / tload in the inline assembly of a solc AST function or modifier body."""
    found: list[dict] = []
    stack = [body] if body else []
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(reversed(node))
            continue
        if not isinstance(node, dict):
            continue
        if node.get("nodeType") == "InlineAssembly":
            refs = {r.get("src", ""): r for r in node.get("externalReferences") or []}
            _yul_walk(node.get("AST"), _Scope(refs, resolve), found, site, line)
            continue
        stack.extend(v for k, v in node.items() if isinstance(v, (dict, list)) and k != "typeDescriptions")
    return found


def summarize(ops: list[dict]) -> dict:
    """Contract-level record stored in the blueprint (``contract["transient"]``)."""
    if not ops:
        return {}
    return {
        "ops": ops,
        "tstore_slots": sorted({o["slot"] for o in ops if o["op"] == "tstore" and o["slot"]}),
        "tload_slots": sorted({o["slot"] for o in ops if o["op"] == "tload" and o["slot"]}),
        "dynamic": sorted({f"{o['op']}({o['expr']}) in {o['site']}" for o in ops if not o["slot"]}),
        "sites": sorted({o["site"] for o in ops}),
    }


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


@dataclass
class TransientPlan:
    slots: list[str]                                  # constant slots written with tstore, as bytes32 hex
    sites: list[str]                                  # "Contract.function f" / "Contract.modifier m"
    dynamic: list[str] = field(default_factory=list)  # tstore calls whose slot is computed at run time
    ignored: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"slots": self.slots, "sites": self.sites, "dynamic": self.dynamic, "ignored": self.ignored}


def _norm_slot(text: str) -> str | None:
    v = parse_number(str(text))
    return slot_hex(v) if v is not None else None


def analyze(target_name: str, lineage: list[dict], settings: dict | None = None) -> TransientPlan | None:
    """Return the Preset 05 plan for a target, or None when nothing in its lineage writes transient storage."""
    settings = settings or {}
    writes: list[tuple[str, dict]] = []
    for c in lineage:
        for op in (c.get("transient") or {}).get("ops", []):
            if op["op"] == "tstore":
                writes.append((c["name"], op))
    extra = [s for s in (_norm_slot(x) for x in settings.get("transient_slots", [])) if s]
    if not writes and not extra:
        return None
    ignore = {s for s in (_norm_slot(x) for x in settings.get("transient_ignore", [])) if s}
    slots = sorted(({op["slot"] for _, op in writes if op["slot"]} | set(extra)) - ignore)
    plan = TransientPlan(
        slots=slots,
        sites=sorted({f"{c}.{op['site'].split(' ', 1)[-1]}" for c, op in writes}),
        dynamic=sorted({f"tstore({op['expr']}) in {c}.{op['site'].split(' ', 1)[-1]}" for c, op in writes if not op["slot"]}),
        ignored=sorted(ignore),
    )
    if plan.dynamic:
        plan.notes.append(
            f"{', '.join(plan.dynamic)}: the slot is computed at run time, so the transient check cannot watch it; "
            f"list the concrete slots under [contracts.{target_name}] transient_slots = [\"0x...\"]")
    if not plan.slots:
        plan.notes.append("no constant transient slot to watch; Preset 05 is not generated for this contract")
    return plan


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def harness_name(target_name: str) -> str:
    return f"{target_name}TransientHarness"


def render_harness(target_name: str, ctor_params: list[str], ctor_args: list[str], payable: bool) -> str:
    name = harness_name(target_name)
    ctor = ""
    if ctor_params:
        ctor = (f"\n    constructor({', '.join(ctor_params)}){' payable' if payable else ''} "
                f"{target_name}({', '.join(ctor_args)}) {{ }}\n")
    return f"""
/// @title {name}
/// @notice Preset 05 (transient storage). {target_name} plus one view that reads its own transient
///         storage, so the handler can look at a slot after a call has returned while the
///         transaction is still running. The suite deploys this instead of {target_name}.
contract {name} is {target_name} {{{ctor}
    function {HARNESS_READER}(bytes32 slot) external view returns (uint256 value) {{
        assembly {{
            value := tload(slot)
        }}
    }}
}}
"""


def render_slot_init(plan: TransientPlan) -> str:
    return "".join(f"\n        transientSlots.push({s});" for s in plan.slots)


def render_handler_helpers(target_name: str, plan: TransientPlan) -> str:
    return f"""
    /// @dev Preset 05: reads every watched slot through the harness. Runs after each successful call,
    ///      still inside the transaction, which is the moment the next call would see the value.
    function _transientCheck() internal {{
        for (uint256 i = 0; i < transientSlots.length; i++) {{
            (bool ok, bytes memory ret) = address(target).staticcall(
                abi.encodeWithSignature("{HARNESS_READER}(bytes32)", transientSlots[i])
            );
            if (!ok || ret.length < 32) continue;
            ghost_transientChecks++;
            uint256 value = abi.decode(ret, (uint256));
            if (value != 0) {{
                ghost_transientLeaks++;
                ghost_transientLeakSlot = transientSlots[i];
                ghost_transientLeakValue = value;
            }}
        }}
    }}

    function transientSlotCount() external view returns (uint256) {{
        return transientSlots.length;
    }}

    function _seed(uint256 s, uint256 k) internal pure returns (uint256) {{
        return uint256(keccak256(abi.encode(s, k)));
    }}
"""


def render_handler_state(target_name: str, plan: TransientPlan) -> str:
    sites = ", ".join(plan.sites)
    return f"""    /// Preset 05: transient slots {target_name} writes with tstore ({sites}).
    bytes32[] internal transientSlots;
    /// Preset 05: slot reads made after successful calls.
    uint256 public ghost_transientChecks;
    /// Preset 05: reads that found a slot still set after the call had returned.
    uint256 public ghost_transientLeaks;
    bytes32 public ghost_transientLeakSlot;
    uint256 public ghost_transientLeakValue;
    /// Preset 05: multi-call sequences run inside one transaction.
    uint256 public ghost_transientSequences;
"""


def _derive(decl: str, k: int) -> str:
    ptype = decl.split()[0]
    raw = f"_seed(s, {k})"
    if ptype == "uint256":
        return raw
    if re.fullmatch(r"uint\d+", ptype):
        return f"{ptype}({raw})"
    if ptype == "int256":
        return f"int256({raw})"
    if re.fullmatch(r"int\d+", ptype):
        return f"{ptype}(int256({raw}))"
    if ptype == "bool":
        return f"{raw} % 2 == 1"
    if re.fullmatch(r"bytes\d+", ptype):
        return f"{ptype}(bytes32({raw}))"
    return raw


def render_sequence(wrappers: list[tuple[str, list[str]]]) -> str:
    """``transientSequence``: 2-4 handler flows back to back inside one transaction."""
    branches = []
    for i, (name, decls) in enumerate(wrappers):
        args = ", ".join(_derive(d, k) for k, d in enumerate(decls))
        kw = "if" if i == 0 else "} else if"
        branches.append(f"            {kw} (op == {i}) {{\n"
                        f"                try this.{name}({args}) {{ }} catch {{ }}")
    body = "\n".join(branches) + "\n            }"
    return f"""
    /// @notice Preset 05: two to four flow calls back to back in this one transaction, the way a
    ///         multicall, a router or a callback chain runs them. Each call checks the transient slots
    ///         when it returns, so a slot one call leaves set is caught before the next call reads it.
    function transientSequence(uint256 seed) external {{
        uint256 steps = 2 + seed % 3;
        for (uint256 i = 0; i < steps; i++) {{
            uint256 s = _seed(seed, i);
            uint256 op = s % {len(wrappers)};
{body}
        }}
        ghost_transientSequences++;
    }}"""


def invariants(target_name: str, plan: TransientPlan) -> list[tuple[str, str, str]]:
    if not plan.slots:
        return []
    return [(
        "invariant_transient_slotsClearedBetweenCalls",
        f"/// @notice Preset 05: every transient slot {target_name} writes reads zero again once a call returns,\n"
        "    ///         so the next call in the same transaction (multicall, router, callback) starts clean.\n"
        "    ///         EIP-1153 only clears transient storage at the end of the transaction.\n"
        f"    /// @dev Watched: {', '.join(plan.slots)}. If a slot is meant to live for the whole transaction,\n"
        f"    ///      list it under [contracts.{target_name}] transient_ignore.",
        '        assertEq(handler.ghost_transientLeaks(), 0, "a transient slot was still set after a call returned; the next call in the same transaction reads it");',
    )]
