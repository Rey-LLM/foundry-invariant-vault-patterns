#!/usr/bin/env python3
"""FoundryGuard parser: compile the project with solc and map its AST into a JSON blueprint.

Nothing here reads Solidity text. ``compiler.py`` asks solc (native, solcjs or
through forge) for the compact JSON AST; this module validates the tree and walks
its nodes:

* ``ContractDefinition``: kind, abstract flag, direct bases and the full C3
  linearization (``linearizedBaseContracts``), resolved by node id to the exact
  declaration, so a parent from OpenZeppelin, Solady or Solmate is known by file
  and origin, not guessed from its name. Interfaces in the lineage are listed.
* ``FunctionDefinition``: kind, visibility, ``stateMutability`` exactly as solc
  reports it, modifiers, virtual / override (with the overridden bases), selector,
  and every parameter with its canonical type, ``typeIdentifier`` and data location.
* ``VariableDeclaration`` (state variables): type, visibility, constant / immutable,
  and for public ones the getter solc generates (mapping keys and array indexes
  become parameters), with its selector.
* function bodies are walked for external hook callbacks (Uniswap v4
  ``beforeSwap`` / ``afterSwap``, ``unlockCallback`` on ``msg.sender``,
  ``*Callback``, ``onFlashLoan``) for Preset 04 (``blueprints/hook_reentrancy.py``).
* function and modifier bodies are walked for ``InlineAssembly`` blocks, and the
  Yul inside them for ``tstore`` / ``tload`` calls (``YulFunctionCall`` nodes),
  with the slot resolved through ``externalReferences`` to the Solidity constant
  it names, for Preset 05 (``blueprints/transient_storage.py``).
* state variables that hold another contract (``IPriceOracle public oracle``,
  ``IERC20 immutable asset``, or an ``address`` that the code casts with
  ``IPriceOracle(oracle)``) become links: where the address is set (constructor,
  initializer or setter parameter, or ``new X()``), which external functions are
  called on it and from where. ``build_ecosystem`` resolves every link to a
  project contract (by the exact interface in each candidate's C3 lineage), a
  mock token, or nothing, and groups the linked contracts into clusters with a
  deploy order and a dependency matrix (Layer 07, ``ecosystem`` in the blueprint).

Every public / external state-changing function is then classified into the
value-flow categories FoundryGuard writes invariants for: ``deposit``,
``withdraw`` and ``stake_lock`` (stake, unstake, lock, claim ...).

Before the walk, ``validate_unit`` checks the tree: a node that misses a field
the walker relies on, a legacy (pre compact) AST, or an AST produced without type
analysis stops the scan with the node path. Compiler errors (syntax, missing
imports, type errors) stop it earlier, in ``compiler.py``.

Usage::

    python3 src/cli/parser.py                         # compile ./src (or ./contracts)
    python3 src/cli/parser.py src -o foundryguard.json
    python3 src/cli/parser.py --solc /usr/bin/solc    # pick the compiler
    python3 src/cli/parser.py --ast out/              # read an AST built elsewhere (forge build --ast)

The output is a deterministic JSON document (``schema: foundryguard.blueprint/v2``)
consumed by ``injector.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

if __package__:
    from . import compiler
    from .blueprints import hook_reentrancy, transient_storage
    from .compiler import Diagnostic, SolidityError
else:  # executed as a plain script directory (python3 src/cli/parser.py)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import compiler  # type: ignore
    from blueprints import hook_reentrancy, transient_storage  # type: ignore
    from compiler import Diagnostic, SolidityError  # type: ignore

SCHEMA = "foundryguard.blueprint/v2"
TOOL_VERSION = "0.7.0"

log = logging.getLogger("foundryguard.parser")

# Directories FoundryGuard scans when no path is given, in priority order.
DEFAULT_SOURCE_DIRS = ("src", "contracts")
# Directories never scanned as targets (dependencies, build output, tests).
EXCLUDED_DIRS = {"lib", "node_modules", "out", "cache", "artifacts", "broadcast", ".git", "test", "tests", "script"}

# --------------------------------------------------------------------------- #
# Classification rules (function names; the syntax itself comes from the AST)
# --------------------------------------------------------------------------- #

# (category, direction, compiled name pattern). Order matters: first match wins,
# so the more specific "un"/"withdraw" patterns come before the broad ones.
CLASSIFICATION_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("stake_lock", "out", re.compile(r"^_?(unstake|unlock|unbond|withdrawStake|withdrawLock|exitStake|cooldown)", re.I)),
    ("stake_lock", "reward", re.compile(r"^_?(claim|getReward|harvest|collect|compound)", re.I)),
    ("stake_lock", "in", re.compile(r"^_?(stake|lock|bond|increaseLock|extendLock|increaseAmount|increaseUnlockTime|createLock|delegateStake)", re.I)),
    ("withdraw", "out", re.compile(r"^_?(withdraw|redeem|exit|removeLiquidity|burn|emergencyWithdraw)", re.I)),
    ("deposit", "in", re.compile(r"^_?(deposit|mint|supply|fund|addLiquidity|provide|topUp)", re.I)),
)

# Parameter names that carry the "how much" of a value flow.
AMOUNT_PARAM = re.compile(r"^_?(amount|amt|assets?|shares?|value|qty|quantity|wad|liquidity|tokens?|lockAmount)_?$", re.I)
SHARE_PARAM = re.compile(r"shares?", re.I)

# View getters the injector can build accounting invariants on.
ACCOUNTING_GETTERS = {
    "totalSupply", "totalAssets", "totalStaked", "totalLocked", "totalDeposits",
    "balanceOf", "stakedOf", "lockedOf", "sharesOf", "earned",
}

# Where a dependency comes from, by a segment of its source unit path.
ORIGINS = (
    ("openzeppelin-contracts-upgradeable", "openzeppelin-upgradeable"),
    ("@openzeppelin/contracts-upgradeable", "openzeppelin-upgradeable"),
    ("openzeppelin", "openzeppelin"),
    ("solady", "solady"),
    ("solmate", "solmate"),
    ("forge-std", "forge-std"),
    ("v4-core", "uniswap-v4"),
    ("v4-periphery", "uniswap-v4"),
    ("uniswap", "uniswap"),
)

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Param:
    type: str
    name: str
    location: str | None = None
    type_id: str | None = None  # solc typeIdentifier, e.g. t_uint256, t_contract$_IERC20_$29

    @property
    def canonical(self) -> str:
        return self.type


@dataclass
class Function:
    name: str
    kind: str  # function | constructor | fallback | receive
    signature: str
    params: list[Param]
    returns: list[Param]
    visibility: str
    mutability: str  # pure | view | nonpayable | payable, from the AST
    modifiers: list[str]
    virtual: bool
    override: bool
    has_body: bool
    line: int
    selector: str | None = None  # 4-byte selector solc computed (public / external only)
    overrides: list[str] = field(default_factory=list)  # bases named in override(A, B)
    category: str | None = None
    direction: str | None = None
    amount_param: str | None = None
    unit: str | None = None
    callbacks: list[dict] = field(default_factory=list)  # external hook calls made in the body


@dataclass
class Contract:
    name: str
    kind: str  # contract | abstract contract | interface | library
    file: str
    line: int
    pragma: str | None
    inherits: list[str]  # direct bases, in declaration order
    functions: list[Function] = field(default_factory=list)
    constructor: Function | None = None
    accounting_getters: list[str] = field(default_factory=list)
    state_vars: list[dict] = field(default_factory=list)  # {name, type, type_id, visibility, mutability, getter}
    categories: dict[str, list[str]] = field(default_factory=dict)
    external: bool = False
    test_helper: bool = False
    hooks: dict = field(default_factory=dict)  # {"callbacks": [...], "call_sites": [...]} when it calls hooks
    transient: dict = field(default_factory=dict)  # tstore / tload ops in its inline assembly (Preset 05)
    fqn: str = ""  # "<file>:<Name>", unique in the project
    abstract: bool = False
    origin: str = "project"  # project | openzeppelin | solady | solmate | forge-std | uniswap | dependency ...
    bases: list[dict] = field(default_factory=list)  # direct bases {name, fqn}
    linearized_bases: list[str] = field(default_factory=list)  # C3 order (self first), as fqns
    interfaces: list[str] = field(default_factory=list)  # interface names anywhere in the lineage
    fully_implemented: bool = True
    links: list[dict] = field(default_factory=list)  # Layer 07: state variables that hold another contract

    @property
    def is_deployable(self) -> bool:
        return self.kind == "contract"


# --------------------------------------------------------------------------- #
# AST validation
# --------------------------------------------------------------------------- #

# Fields the walker reads, per node type. A node without them is malformed.
NODE_FIELDS: dict[str, tuple[str, ...]] = {
    "SourceUnit": ("id", "absolutePath", "nodes"),
    "PragmaDirective": ("literals",),
    "ImportDirective": ("file", "absolutePath"),
    "ContractDefinition": ("id", "name", "contractKind", "baseContracts", "linearizedBaseContracts", "nodes", "src"),
    "InheritanceSpecifier": ("baseName",),
    "FunctionDefinition": ("id", "kind", "name", "parameters", "returnParameters", "stateMutability",
                           "visibility", "implemented", "modifiers", "src"),
    "ModifierInvocation": ("modifierName",),
    "ParameterList": ("parameters",),
    "VariableDeclaration": ("name", "typeDescriptions", "src"),
}


class ASTValidationError(SolidityError):
    pass


def _check_src(src, path: str, problems: list[str]) -> None:
    parts = src.split(":") if isinstance(src, str) else []
    if len(parts) != 3 or not all(p.lstrip("-").isdigit() for p in parts):
        problems.append(f"{path}: bad src {src!r} (expected start:length:file)")


def validate_unit(unit: dict, name: str = "") -> None:
    """Raise ``ASTValidationError`` if the SourceUnit cannot be trusted for the walk."""
    problems: list[str] = []
    label = name or str(unit.get("absolutePath") or "<unit>")
    if not isinstance(unit, dict) or unit.get("nodeType") != "SourceUnit":
        if isinstance(unit, dict) and unit.get("name") == "SourceUnit":
            raise ASTValidationError(f"{label}: legacy solc AST (`--ast-json`, solc < 0.8)",
                                     hint="produce the compact AST: `solc --ast-compact-json` or Standard JSON")
        raise ASTValidationError(f"{label}: not a SourceUnit node")

    def need(node: dict, path: str) -> bool:
        nt = node.get("nodeType")
        missing = [k for k in NODE_FIELDS.get(nt, ()) if k not in node]
        if missing:
            problems.append(f"{path}: {nt} without {', '.join(missing)}")
            return False
        if "src" in node:
            _check_src(node["src"], path, problems)
        return True

    def var(node: dict, path: str) -> None:
        if not isinstance(node, dict) or node.get("nodeType") != "VariableDeclaration":
            problems.append(f"{path}: expected VariableDeclaration, got {node.get('nodeType') if isinstance(node, dict) else type(node).__name__}")
            return
        if need(node, path) and not (node.get("typeDescriptions") or {}).get("typeString"):
            problems.append(f"{path}: no typeDescriptions.typeString (AST produced without type analysis)")

    def plist(node, path: str) -> None:
        if not isinstance(node, dict) or node.get("nodeType") != "ParameterList":
            problems.append(f"{path}: expected ParameterList")
            return
        if need(node, path):
            for i, p in enumerate(node["parameters"]):
                var(p, f"{path}.parameters[{i}]")

    need(unit, label)
    for i, node in enumerate(unit.get("nodes") or []):
        if not isinstance(node, dict) or "nodeType" not in node:
            problems.append(f"{label}.nodes[{i}]: not an AST node")
            continue
        nt = node["nodeType"]
        path = f"{label}.nodes[{i}]<{nt}{(' ' + str(node.get('name'))) if node.get('name') else ''}>"
        if nt in ("PragmaDirective", "ImportDirective"):
            need(node, path)
        elif nt == "ContractDefinition":
            if not need(node, path):
                continue
            for j, base in enumerate(node["baseContracts"]):
                if need(base, f"{path}.baseContracts[{j}]") and "referencedDeclaration" not in (base["baseName"] or {}):
                    problems.append(f"{path}.baseContracts[{j}]: base without referencedDeclaration (unresolved)")
            for j, member in enumerate(node["nodes"]):
                mt = member.get("nodeType") if isinstance(member, dict) else None
                mpath = f"{path}.nodes[{j}]<{mt} {member.get('name', '') if isinstance(member, dict) else ''}>"
                if mt == "FunctionDefinition":
                    if need(member, mpath):
                        plist(member["parameters"], f"{mpath}.parameters")
                        plist(member["returnParameters"], f"{mpath}.returnParameters")
                        for k, m in enumerate(member["modifiers"]):
                            need(m, f"{mpath}.modifiers[{k}]")
                elif mt == "VariableDeclaration":
                    var(member, mpath)
                elif mt is None:
                    problems.append(f"{mpath}: not an AST node")
        if len(problems) > 20:
            break
    if problems:
        raise ASTValidationError(f"{label}: {len(problems)} invalid AST node(s)",
                                 [Diagnostic("error", "ASTValidationError", p, file=label) for p in problems[:20]])


# --------------------------------------------------------------------------- #
# Node helpers
# --------------------------------------------------------------------------- #

_DROP_WORDS = {"memory", "calldata", "storage", "pointer", "ref", "slice",
               "contract", "struct", "enum", "library", "interface"}


def normalize_type(type_string: str) -> str:
    """solc typeString -> the type as written in a signature (``contract IERC20`` -> ``IERC20``)."""
    words = [w for w in type_string.replace("(", "( ").replace(")", " )").split() if w not in _DROP_WORDS]
    out: list[str] = []
    for w in words:
        if w == "payable" and out and out[-1] == "address":
            continue
        out.append(w)
    return " ".join(out).replace("( ", "(").replace(" )", ")")


def ast_type(node: dict) -> str:
    return normalize_type((node.get("typeDescriptions") or {}).get("typeString") or "")


def _line(source: bytes | None, src: str) -> int:
    if not source or not src:
        return 0
    start = int(src.split(":")[0])
    return source[:start].count(b"\n") + 1 if start >= 0 else 0


def _params(node: dict | None) -> list[Param]:
    out = []
    for i, p in enumerate((node or {}).get("parameters", [])):
        loc = p.get("storageLocation")
        out.append(Param(type=ast_type(p), name=p.get("name") or f"arg{i}",
                         location=loc if loc in ("memory", "calldata", "storage") else None,
                         type_id=(p.get("typeDescriptions") or {}).get("typeIdentifier")))
    return out


def _ref_name(node: dict | None) -> str:
    node = node or {}
    return (node.get("name") or node.get("namePath") or "").split(".")[-1]


def build_rules(config: dict | None) -> tuple[tuple[str, str, re.Pattern[str]], ...]:
    """Prepend user rules from ``foundryguard.toml`` ``[classify]`` to the built-in ones.

    Config shape (names are exact function names or regexes)::

        [classify]
        deposit = ["enter", "join"]           # category "deposit", direction "in"
        withdraw = ["leave"]                   # category "withdraw", direction "out"
        stake_in = ["boost"]
        stake_out = ["unboost"]
        reward = ["getPaid"]
        ignore = ["mintFee"]                   # never treat these as value flows
    """
    cfg = (config or {}).get("classify", {})
    mapping = {
        "deposit": ("deposit", "in"), "withdraw": ("withdraw", "out"),
        "stake_in": ("stake_lock", "in"), "stake_out": ("stake_lock", "out"), "reward": ("stake_lock", "reward"),
        "ignore": ("__ignore__", ""),
    }
    rules: list[tuple[str, str, re.Pattern[str]]] = []
    for key, names in cfg.items():
        if key not in mapping:
            log.warning("foundryguard.toml: unknown [classify] key %r (expected one of %s)", key, ", ".join(mapping))
            continue
        category, direction = mapping[key]
        for n in names:
            rules.append((category, direction, re.compile(n if any(ch in n for ch in "^$*+?[(|\\") else f"^{re.escape(n)}$")))
    # Ignore rules must win over everything, user rules over built-ins.
    rules.sort(key=lambda r: r[0] != "__ignore__")
    return tuple(rules) + CLASSIFICATION_RULES


def _is_uint(p: Param) -> bool:
    return (p.type_id or "").startswith("t_uint") or (p.type.startswith("uint") and p.type[4:].isdigit()) or p.type == "uint"


def classify(fn: Function, rules: tuple[tuple[str, str, re.Pattern[str]], ...] = CLASSIFICATION_RULES) -> None:
    """Attach category/direction/amount metadata for value-flow functions."""
    if fn.kind != "function" or fn.visibility not in {"public", "external"} or fn.mutability in {"view", "pure"}:
        return
    if hook_reentrancy.is_callback_name(fn.name):
        return  # unlockCallback / beforeSwap ... are entry points for the caller, not value flows
    for category, direction, pattern in rules:
        if pattern.match(fn.name):
            if category == "__ignore__":
                return
            fn.category, fn.direction = category, direction
            break
    else:
        return
    uints = [p for p in fn.params if _is_uint(p)]
    named = next((p for p in uints if AMOUNT_PARAM.match(p.name)), None)
    if named:
        fn.amount_param = named.name
    elif len(uints) == 1:
        fn.amount_param = uints[0].name
    if fn.amount_param:
        fn.unit = "shares" if SHARE_PARAM.search(fn.amount_param) else "assets"
    elif fn.mutability == "payable" and fn.direction == "in":
        fn.amount_param, fn.unit = "msg.value", "native"


# --------------------------------------------------------------------------- #
# Walk
# --------------------------------------------------------------------------- #


def _function(node: dict, source: bytes | None, rules) -> Function:
    kind = node["kind"]
    name = node.get("name") or kind
    params = _params(node["parameters"])
    mods = [_ref_name(m.get("modifierName")) for m in node["modifiers"]
            if m.get("kind", "modifierInvocation") == "modifierInvocation"]
    overrides = node.get("overrides")
    fn = Function(
        name=name, kind=kind, signature=f"{name}({','.join(p.type for p in params)})", params=params,
        returns=_params(node["returnParameters"]), visibility=node["visibility"],
        mutability=node["stateMutability"], modifiers=[m for m in mods if m],
        virtual=bool(node.get("virtual")), override=overrides is not None,
        has_body=bool(node["implemented"]), line=_line(source, node["src"]),
        selector=node.get("functionSelector"),
        overrides=[_ref_name(o) for o in (overrides or {}).get("overrides", [])],
        callbacks=hook_reentrancy.detect_callbacks_ast(node.get("body")),
    )
    classify(fn, rules)
    return fn


def _getter(var: dict) -> dict:
    """The external getter solc generates for a public state variable."""
    params: list[str] = []
    t = var.get("typeName")
    while isinstance(t, dict) and t.get("nodeType") in ("Mapping", "ArrayTypeName"):
        if t["nodeType"] == "Mapping":
            params.append(ast_type(t["keyType"]))
            t = t["valueType"]
        else:
            params.append("uint256")
            t = t["baseType"]
    ret = ast_type(t) if isinstance(t, dict) else ast_type(var)
    name = var["name"]
    return {"signature": f"{name}({','.join(params)})", "selector": var.get("functionSelector"),
            "params": params, "returns": [ret]}


def _state_var(var: dict) -> dict:
    mutability = var.get("mutability") or ("constant" if var.get("constant") else "mutable")
    out = {"name": var["name"], "type": ast_type(var),
           "type_id": (var.get("typeDescriptions") or {}).get("typeIdentifier"),
           "visibility": var.get("visibility", "internal"), "mutability": mutability}
    if out["visibility"] == "public":
        out["getter"] = _getter(var)
    return out


def _pragma(unit: dict) -> str | None:
    for node in unit.get("nodes", []):
        if node.get("nodeType") == "PragmaDirective" and node["literals"][:1] == ["solidity"]:
            text = ""
            for t in node["literals"][1:]:
                if t[:1] in "^~<>=|" and text and text[-1] not in "^~<>=| ":
                    text += " "
                text += t
            return text
    return None


def _is_target_path(path: str, paths: list[str], root: Path) -> bool:
    if path.endswith((".t.sol", ".s.sol")):
        return False
    bases = list(paths) or [d for d in DEFAULT_SOURCE_DIRS if (root / d).is_dir()]
    for b in bases:
        b = b.rstrip("/")
        if path == b or path.startswith(b + "/"):
            inner = Path(path[len(b) + 1:]).parts[:-1] if path != b else ()
            return not any(part in EXCLUDED_DIRS for part in inner)
    return False


def origin_of(path: str, external: bool) -> str:
    if not external:
        return "project"
    low = path.lower()
    for key, label in ORIGINS:
        if key in low:
            return label
    return "dependency" if low.startswith(("lib/", "node_modules/", "@")) else "project"


def _imports_test_lib(unit: dict) -> bool:
    for node in unit.get("nodes", []):
        if node.get("nodeType") == "ImportDirective":
            for p in (node.get("file", ""), node.get("absolutePath", "")):
                if p.startswith(("forge-std/", "ds-test/")) or "/forge-std/" in p or "/ds-test/" in p:
                    return True
    return False


# --------------------------------------------------------------------------- #
# Layer 07: links to other contracts
# --------------------------------------------------------------------------- #

# typeIdentifier of a contract or interface type, e.g. t_contract$_IPriceOracle_$12 (the number is the node id).
CONTRACT_TID = re.compile(r"t_contract\$_(.+?)_\$(\d+)")
# Role of a linked contract, from its type name (first match wins), then from the variable name.
LINK_ROLES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("hook", re.compile(r"Hook|Callback", re.I)),
    ("oracle", re.compile(r"Oracle|PriceFeed|Feed$|Aggregator|Price|RateProvider|TWAP", re.I)),
    ("vault", re.compile(r"Vault|4626|Strategy", re.I)),
    ("token", re.compile(r"^(I?ERC20\w*|I?ERC777\w*|IWETH\w*|WETH\w*|\w*Token\w*|MockERC20)$", re.I)),
    ("pool", re.compile(r"Pool|Pair|Router|Market|Amm|Comptroller|Manager", re.I)),
)
# Address parameters / variables whose name says token, for `address token_` style links.
TOKEN_VAR = re.compile(r"(token|asset|underlying|want|collateral|weth)", re.I)


def link_role(type_name: str, var_name: str) -> str:
    for role, pattern in LINK_ROLES:
        if pattern.search(type_name) if role != "token" else pattern.match(type_name):
            return role
    if TOKEN_VAR.search(var_name):
        return "token"
    for role, pattern in LINK_ROLES[:3]:
        if pattern.search(var_name):
            return role
    return "contract"


def _walk(node):
    """Every dict node below ``node`` (any order)."""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            yield n
            stack.extend(v for v in n.values() if isinstance(v, (dict, list)))
        elif isinstance(n, list):
            stack.extend(n)


def _unwrap(expr):
    """``IFoo(x)``, ``address(x)``, ``payable(x)`` and ``(x)`` -> ``x``."""
    while isinstance(expr, dict):
        if (expr.get("nodeType") == "FunctionCall" and expr.get("kind") == "typeConversion"
                and len(expr.get("arguments") or []) == 1):
            expr = expr["arguments"][0]
        elif expr.get("nodeType") == "TupleExpression" and len(expr.get("components") or []) == 1:
            expr = expr["components"][0]
        else:
            break
    return expr


def _ref(expr) -> int | None:
    expr = _unwrap(expr)
    if isinstance(expr, dict) and expr.get("nodeType") == "Identifier":
        return expr.get("referencedDeclaration")
    return None


def _contract_of_tid(tid: str | None, group: str, index: dict) -> tuple[str, dict | None, str | None]:
    """(type name, ContractDefinition or None, fqn or None) for a contract typeIdentifier."""
    m = CONTRACT_TID.search(tid or "")
    if not m:
        return "", None, None
    hit = index.get((group, int(m.group(2))))
    if hit:
        return hit[1]["name"], hit[1], f"{hit[0]}:{hit[1]['name']}"
    return m.group(1), None, None


def _site_kind(member: dict) -> str:
    if member.get("kind") == "constructor":
        return "constructor"
    mods = [_ref_name(m.get("modifierName")) for m in member.get("modifiers", [])]
    if any(m in ("initializer", "reinitializer", "onlyInitializing") for m in mods) or \
            (member.get("name") or "").startswith("initialize"):
        return "initializer"
    if member.get("visibility") in ("public", "external"):
        return "setter"
    return "internal"


def detect_links(node: dict, group: str, index: dict, functions: dict[int, Function]) -> list[dict]:
    """State variables of ``node`` that hold another contract, and how the contract uses them.

    A variable counts when its declared type is a contract or interface, or when it is an ``address`` that
    the code converts to one (``IPriceOracle(oracle).price()``). For each one the walk records the
    functions whose parameter is assigned to it, a ``new X(...)`` that creates it, and every external
    function called on it with the function that calls it.
    """
    state = {m["id"]: m for m in node["nodes"]
             if isinstance(m, dict) and m.get("nodeType") == "VariableDeclaration"
             and m.get("stateVariable", True) and not m.get("constant")}
    links: dict[int, dict] = {}
    addresses: dict[int, dict] = {}
    for vid, var in state.items():
        tid = (var.get("typeDescriptions") or {}).get("typeIdentifier") or ""
        if tid.startswith("t_contract$_"):
            name, dep, dep_fqn = _contract_of_tid(tid, group, index)
            links[vid] = _new_link(var, name, dep, dep_fqn, "declared")
        elif tid in ("t_address", "t_address_payable"):
            addresses[vid] = var

    sites: dict[int, list[dict]] = {}
    created: dict[int, str] = {}
    calls: dict[int, set[str]] = {}
    used_in: dict[int, set[str]] = {}
    for member in node["nodes"]:
        nt = member.get("nodeType") if isinstance(member, dict) else None
        if nt not in ("FunctionDefinition", "ModifierDefinition") or not member.get("body"):
            continue
        fn = functions.get(member.get("id"))
        label = (fn.signature if fn and fn.kind == "function" else fn.kind) if fn else f"modifier {member.get('name')}"
        params = {p["id"]: (i, p) for i, p in enumerate((member.get("parameters") or {}).get("parameters", []))}
        for n in _walk(member["body"]):
            t = n.get("nodeType")
            if t == "FunctionCall" and n.get("kind") == "typeConversion" and n.get("arguments"):
                ref = _ref(n["arguments"][0])
                if ref in addresses and ref not in links:
                    tid = ((n.get("expression") or {}).get("typeDescriptions") or {}).get("typeIdentifier")
                    name, dep, dep_fqn = _contract_of_tid(tid, group, index)
                    if name:
                        links[ref] = _new_link(addresses[ref], name, dep, dep_fqn, "cast")
            elif t == "MemberAccess":
                ref = _ref(n.get("expression"))
                ftid = (n.get("typeDescriptions") or {}).get("typeIdentifier") or ""
                if ref in state and ftid.startswith("t_function_external"):
                    calls.setdefault(ref, set()).add(n.get("memberName", ""))
                    used_in.setdefault(ref, set()).add(label)
            elif t == "Assignment":
                ref = _ref(n.get("leftHandSide"))
                if ref not in state:
                    continue
                rhs = _unwrap(n.get("rightHandSide"))
                if isinstance(rhs, dict) and rhs.get("nodeType") == "Identifier" and rhs.get("referencedDeclaration") in params:
                    i, p = params[rhs["referencedDeclaration"]]
                    sites.setdefault(ref, []).append({
                        "function": label, "kind": _site_kind(member), "param": p.get("name") or f"arg{i}", "index": i,
                        "params": len(params), "modifiers": list(fn.modifiers) if fn else [],
                    })
                elif (isinstance(rhs, dict) and rhs.get("nodeType") == "FunctionCall"
                      and (rhs.get("expression") or {}).get("nodeType") == "NewExpression"):
                    tn = (rhs["expression"].get("typeName") or {})
                    created[ref] = _ref_name(tn.get("pathNode") or tn) or ""

    out = []
    for vid, link in links.items():
        link["set_in"] = sorted(sites.get(vid, []), key=lambda s: (s["kind"] != "constructor", s["function"]))
        link["created"] = created.get(vid)
        link["calls"] = sorted(calls.get(vid, set()))
        link["used_in"] = sorted(used_in.get(vid, set()))
        out.append(link)
    ctor = next((f for f in functions.values() if f.kind == "constructor"), None)
    for link in out:
        # Set through an internal helper, or not at all in this unit: a constructor parameter of the same
        # contract type is the best evidence left.
        if ctor and not link["created"] and all(s["kind"] == "internal" for s in link["set_in"]):
            same = [i for i, p in enumerate(ctor.params) if link["type_id"] and p.type_id == link["type_id"]]
            if len(same) == 1:
                p = ctor.params[same[0]]
                link["set_in"].insert(0, {"function": "constructor", "kind": "constructor", "param": p.name,
                                          "index": same[0], "params": len(ctor.params), "modifiers": [], "inferred": True})
    return sorted(out, key=lambda x: x["line"])


def _new_link(var: dict, type_name: str, dep: dict | None, dep_fqn: str | None, how: str) -> dict:
    visibility = var.get("visibility", "internal")
    tid = (var.get("typeDescriptions") or {}).get("typeIdentifier")
    return {
        "var": var["name"], "type": type_name, "type_fqn": dep_fqn, "type_id": tid if how == "declared" else None,
        "declared_as": ast_type(var), "how": how,
        "type_kind": ("abstract contract" if dep and dep.get("abstract") else dep["contractKind"]) if dep else None,
        "role": link_role(type_name, var["name"]), "visibility": visibility,
        "mutability": var.get("mutability") or "mutable",
        "getter": f"{var['name']}()" if visibility == "public" else None,
        "line": 0, "_src": var.get("src"),
    }


def build_ecosystem(contracts: list[Contract], config: dict | None = None) -> dict:
    """Resolve every link of every project contract and group linked contracts into clusters.

    A link resolves to a project contract when its type is that (deployable) contract, or an interface /
    abstract contract in exactly one deployable project contract's C3 lineage (``[ecosystem] bind`` picks
    when there are several). Token links get a mock unless bound, hook links are left to Preset 04.
    """
    cfg = (config or {}).get("ecosystem", {})
    bind = {str(k): str(v) for k, v in (cfg.get("bind") or {}).items()}
    by_fqn = {c.fqn: c for c in contracts}
    members = [c for c in contracts if not c.external and not c.test_helper and c.kind == "contract"]
    names = {c.name for c in members}
    edges: list[dict] = []
    for c in members:
        own = [(l, None) for l in c.links]
        for f in c.linearized_bases[1:]:
            parent = by_fqn.get(f)
            if parent is not None:
                own += [(l, parent.name) for l in parent.links]
        seen: set[str] = set()
        for link, inherited in own:
            if link["var"] in seen:
                continue
            seen.add(link["var"])
            edges.append(_resolve(c, link, inherited, members, names, bind))

    adj: dict[str, set[str]] = {n: set() for n in names}
    for e in edges:
        if e["status"] in ("member", "created"):
            adj[e["from"]].add(e["to"])
            adj[e["to"]].add(e["from"])
    clusters, seen_nodes = [], set()
    for start in sorted(names):
        if start in seen_nodes or not adj[start]:
            continue
        comp, stack = set(), [start]
        while stack:
            n = stack.pop()
            if n not in comp:
                comp.add(n)
                stack.extend(adj[n] - comp)
        seen_nodes |= comp
        clusters.append(_cluster(sorted(comp), edges))
    return {
        "links": sum(len(c.links) for c in contracts if not c.external),
        "edges": edges,
        "clusters": clusters,
    }


def _resolve(c: Contract, link: dict, inherited: str | None, members: list[Contract], names: set[str],
             bind: dict[str, str]) -> dict:
    sites = link.get("set_in") or []
    deploy = next((s for s in sites if s["kind"] in ("constructor", "initializer")), None)
    setter = next((s for s in sites if s["kind"] == "setter" and s["params"] == 1), None)
    if link.get("created"):
        via = "created"
    elif deploy:
        via = deploy["kind"]
    elif setter:
        via = "setter"
    else:
        via = "unknown"
    site = deploy or setter
    edge = {
        "from": c.name, "var": link["var"], "type": link["type"], "role": link["role"], "via": via,
        "param": site["param"] if site else None, "index": site["index"] if site else None,
        "function": site["function"] if site else None, "getter": link.get("getter"),
        "calls": link.get("calls", []), "used_in": link.get("used_in", []), "inherited_from": inherited,
        "to": None, "status": "unresolved", "candidates": [],
    }
    chosen = bind.get(f"{c.name}.{link['var']}") or bind.get(link["type"])
    if link.get("created"):
        chosen = chosen or link["created"]
    if chosen:
        if chosen in names and chosen != c.name:
            edge.update(to=chosen, status="created" if via == "created" else "member", candidates=[chosen])
        elif chosen.lower() == "mock":
            edge["status"] = "mock"
        return edge
    if link["role"] == "hook":
        edge["status"] = "hook"
        return edge
    concrete = link.get("type_kind") == "contract" and link["type"] in names
    if concrete and link["type"] != c.name:
        edge.update(to=link["type"], status="member", candidates=[link["type"]])
        return edge
    if link["role"] == "token":
        edge["status"] = "mock"
        return edge
    cands = sorted(m.name for m in members if m is not c and (
        (link.get("type_fqn") and link["type_fqn"] in m.linearized_bases[1:])
        or (not link.get("type_fqn") and (link["type"] in m.interfaces or link["type"] in m.inherits))))
    edge["candidates"] = cands
    if cands:
        edge.update(to=cands[0], status="member")
    return edge


def _cluster(comp: list[str], edges: list[dict]) -> dict:
    inner = [e for e in edges if e["from"] in comp and e["to"] in comp and e["status"] in ("member", "created")]
    # Deploy order: a contract whose constructor / initializer takes another one's address comes after it.
    needs = {n: {e["to"] for e in inner if e["from"] == n and e["via"] in ("constructor", "initializer")} for n in comp}
    order, done, cycles = [], set(), []
    pending = list(comp)
    while pending:
        ready = [n for n in pending if needs[n] <= done]
        if not ready:
            cycles.append(sorted(pending))
            order.extend(sorted(pending))
            break
        for n in sorted(ready):
            order.append(n)
            done.add(n)
            pending.remove(n)
    incoming = {n: sum(1 for e in inner if e["to"] == n) for n in comp}
    roots = [n for n in order if incoming[n] == 0]
    if len(roots) == 1:
        name = roots[0]
    else:
        name = max(order, key=lambda n: (incoming[n], -order.index(n)))
    return {
        "name": name,
        "members": order,
        "roots": roots,
        "cycles": cycles,
        "matrix": {"order": order,
                   "rows": [[1 if any(e["from"] == a and e["to"] == b for e in inner) else 0 for b in order] for a in order]},
    }



def contracts_from_ast(result: "compiler.CompileResult", root: Path, paths: list[str],
                       rules=CLASSIFICATION_RULES) -> list[Contract]:
    """Walk validated SourceUnits into ``Contract`` records (targets plus everything they import)."""
    units = result.units
    for name, unit in units.items():
        validate_unit(unit, name)

    # (group, node id) -> (unit name, ContractDefinition); ids are only unique within one compile job.
    index: dict[tuple[str, int], tuple[str, dict]] = {}
    for name, unit in units.items():
        group = result.groups.get(name, "")
        for node in unit["nodes"]:
            if node.get("nodeType") == "ContractDefinition":
                index[(group, node["id"])] = (name, node)

    def fqn(unit_name: str, node: dict) -> str:
        return f"{unit_name}:{node['name']}"

    # (group, node id) -> constant VariableDeclaration, file level or in a contract. Inline assembly can only
    # name constants that are plain numbers, so these are enough to resolve tstore / tload slots.
    constants: dict[tuple[str, int], dict] = {}
    for name, unit in units.items():
        group = result.groups.get(name, "")
        for node in unit["nodes"]:
            members = node.get("nodes", []) if node.get("nodeType") == "ContractDefinition" else [node]
            for m in members:
                if isinstance(m, dict) and m.get("nodeType") == "VariableDeclaration" and m.get("constant"):
                    constants[(group, m["id"])] = m

    # Emit targets and the units they reach through imports (dependencies stay context, not targets).
    targets = sorted(n for n in units if _is_target_path(n, paths, root))
    by_path = {n: n for n in units}
    keep: set[str] = set()
    queue = list(targets)
    while queue:
        n = queue.pop()
        if n in keep:
            continue
        keep.add(n)
        for node in units[n]["nodes"]:
            if node.get("nodeType") == "ImportDirective" and node["absolutePath"] in by_path:
                queue.append(node["absolutePath"])

    contracts: list[Contract] = []
    for name in sorted(keep):
        unit = units[name]
        group = result.groups.get(name, "")
        source = compiler.read_source(root, name)
        pragma = _pragma(unit)
        external = not _is_target_path(name, paths, root)
        test_helper = _imports_test_lib(unit)
        for node in unit["nodes"]:
            if node.get("nodeType") != "ContractDefinition":
                continue
            ck = node["contractKind"]
            lineage: list[str] = []
            interfaces: list[str] = []
            for base_id in node["linearizedBaseContracts"]:
                hit = index.get((group, base_id))
                if hit is None:
                    raise ASTValidationError(f"{name}: {node['name']} inherits node {base_id}, which is not in the AST",
                                             hint="the AST is incomplete; rebuild it with every source of the project")
                lineage.append(fqn(*hit))
                if hit[1]["contractKind"] == "interface" and hit[1] is not node:
                    interfaces.append(hit[1]["name"])
            bases = []
            for b in node["baseContracts"]:
                hit = index.get((group, b["baseName"]["referencedDeclaration"]))
                bases.append({"name": hit[1]["name"] if hit else _ref_name(b["baseName"]),
                              "fqn": fqn(*hit) if hit else None})
            c = Contract(
                name=node["name"], kind="abstract contract" if (ck == "contract" and node.get("abstract")) else ck,
                file=name, line=_line(source, node["src"]), pragma=pragma, inherits=[b["name"] for b in bases],
                external=external, test_helper=test_helper, fqn=fqn(name, node), abstract=bool(node.get("abstract")),
                origin=origin_of(name, external), bases=bases, linearized_bases=lineage, interfaces=interfaces,
                fully_implemented=bool(node.get("fullyImplemented", True)),
            )
            def lookup(decl_id, _g=group):
                return constants.get((_g, decl_id))

            def resolve(decl_id, _lookup=lookup):
                return transient_storage.constant_value(_lookup(decl_id), _lookup)

            transient_ops: list[dict] = []
            fn_by_id: dict[int, Function] = {}
            for member in node["nodes"]:
                nt = member.get("nodeType")
                if nt in ("FunctionDefinition", "ModifierDefinition") and member.get("body"):
                    kind = "modifier" if nt == "ModifierDefinition" else (member.get("kind") or "function")
                    site = f"{kind} {member.get('name') or kind}"
                    transient_ops += transient_storage.scan(member["body"], resolve, site,
                                                            lambda src, _s=source: _line(_s, src))
                if nt == "FunctionDefinition":
                    fn = _function(member, source, rules)
                    fn_by_id[member["id"]] = fn
                    if fn.kind == "constructor":
                        c.constructor = fn
                    else:
                        c.functions.append(fn)
                        if (fn.name in ACCOUNTING_GETTERS and fn.mutability in ("view", "pure")
                                and fn.visibility in ("public", "external")):
                            c.accounting_getters.append(fn.name)
                elif nt == "VariableDeclaration" and member.get("stateVariable", True):
                    var = _state_var(member)
                    c.state_vars.append(var)
                    if var["visibility"] == "public" and var["name"] in ACCOUNTING_GETTERS:
                        c.accounting_getters.append(var["name"])
            c.accounting_getters = sorted(set(c.accounting_getters))
            c.transient = transient_storage.summarize(transient_ops)
            c.links = detect_links(node, group, index, fn_by_id)
            for link in c.links:
                link["line"] = _line(source, link.pop("_src") or "")
            contracts.append(c)
    return contracts


# --------------------------------------------------------------------------- #
# Project discovery
# --------------------------------------------------------------------------- #


def discover_sources(root: Path, paths: Iterable[str]) -> list[Path]:
    paths = list(paths)
    targets = [root / p for p in paths] if paths else [root / d for d in DEFAULT_SOURCE_DIRS if (root / d).is_dir()]
    if not targets:
        raise SystemExit(f"foundryguard: no source directory found under {root} (looked for {', '.join(DEFAULT_SOURCE_DIRS)})")
    files: set[Path] = set()
    for t in targets:
        if t.is_file() and t.suffix == ".sol":
            files.add(t.resolve())
            continue
        if not t.is_dir():
            raise SystemExit(f"foundryguard: path not found: {t}")
        for dirpath, dirnames, filenames in os.walk(t):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for f in filenames:
                if f.endswith(".sol") and not f.endswith((".t.sol", ".s.sol")):
                    files.add((Path(dirpath) / f).resolve())
    if not files:
        raise SystemExit(f"foundryguard: no .sol files under {', '.join(str(t) for t in targets)}")
    return sorted(files)


def rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def get_ast(root: Path, paths: list[str], compiler_kind: str = "auto", solc: str | None = None,
            ast_path: str | None = None, build_dir: str = "out", run_build: bool = True) -> "compiler.CompileResult":
    """Compile (or load) the project's AST with the requested driver."""
    if ast_path:
        p = Path(ast_path)
        return compiler.read_prebuilt(p if p.is_absolute() else root / p)
    if not run_build:
        p = Path(build_dir)
        return compiler.read_prebuilt(p if p.is_absolute() else root / p)
    if compiler_kind == "forge":
        return compiler.compile_with_forge(root, build_dir)
    files = [rel(root, f) for f in discover_sources(root, paths)]
    if compiler_kind in ("solc", "solcjs") or solc:
        return compiler.compile_with_solc(root, files, compiler_kind, solc)
    # auto: a local solc / solcjs first, forge when that is all there is.
    found = compiler.discover_compilers("auto")
    if found:
        try:
            return compiler.compile_with_solc(root, files, "auto")
        except SolidityError as exc:
            if not (exc.headline.startswith("no installed compiler satisfies") and shutil.which("forge")):
                raise
            log.info("falling back to forge build: %s", exc.headline)
    if shutil.which("forge"):
        return compiler.compile_with_forge(root, build_dir)
    raise SolidityError("no Solidity compiler found",
                        hint="install solc or Foundry, `npm install -g solc`, or pass --solc PATH / --ast PATH")


def build_blueprint(root: Path, paths: list[str], config: dict | None = None, compiler_kind: str = "auto",
                    solc: str | None = None, ast_path: str | None = None, build_dir: str = "out",
                    run_build: bool = True, save_ast: str | None = None) -> dict:
    """Compile the project and return the blueprint dict."""
    root = root.resolve()
    rules = build_rules(config)
    result = get_ast(root, paths, compiler_kind, solc, ast_path, build_dir, run_build)
    if save_ast:
        out = Path(save_ast) if Path(save_ast).is_absolute() else root / save_ast
        raw = result.raw or {"sources": {n: {"ast": u} for n, u in result.units.items()}}
        out.write_text(json.dumps({"sources": raw.get("sources", {})}, sort_keys=True) + "\n")
    contracts = contracts_from_ast(result, root, paths, rules)
    remaps = compiler.load_remappings(root)
    return _finish_blueprint(root, paths, remaps, contracts, result, config)


def _finish_blueprint(root: Path, paths: list[str], remaps: list[str], contracts: list[Contract],
                      result: "compiler.CompileResult", config: dict | None = None) -> dict:
    for c in contracts:
        cats: dict[str, list[str]] = {}
        for fn in c.functions:
            if fn.category:
                cats.setdefault(fn.category, []).append(fn.signature)
        c.categories = cats
        fns = c.functions + ([c.constructor] if c.constructor else [])
        sites = [fn.name for fn in fns if fn.callbacks]
        if sites:
            c.hooks = {"callbacks": sorted({cb["name"] for fn in fns for cb in fn.callbacks}), "call_sites": sites}

    contracts.sort(key=lambda c: (c.external, c.file, c.line))
    ecosystem = build_ecosystem(contracts, config)
    targets = [c for c in contracts if not c.external and not c.test_helper]
    target_files = {c.file for c in contracts if not c.external}
    summary = {
        "files_scanned": len(target_files),
        "source_units": len(result.units),
        "contracts": len(targets),
        "external_contracts": sum(1 for c in contracts if c.external),
        "test_helpers": sum(1 for c in contracts if c.test_helper and not c.external),
        "deposit_functions": sum(len(c.categories.get("deposit", [])) for c in targets),
        "withdraw_functions": sum(len(c.categories.get("withdraw", [])) for c in targets),
        "stake_lock_functions": sum(len(c.categories.get("stake_lock", [])) for c in targets),
        "hook_contracts": sum(1 for c in targets if c.hooks),
        "transient_contracts": sum(1 for c in targets if c.transient),
        "linked_contracts": sum(1 for c in targets if c.links),
        "ecosystems": len(ecosystem["clusters"]),
    }
    warnings = [d.as_dict() for d in result.diagnostics if d.file in target_files]
    return {
        "schema": SCHEMA,
        "tool": {"name": "foundryguard", "version": TOOL_VERSION},
        "backend": "ast",
        "compiler": {"driver": result.driver, "version": result.version},
        "root": root.as_posix(),
        "source_paths": list(paths) or [d for d in DEFAULT_SOURCE_DIRS if (root / d).is_dir()],
        "remappings": remaps,
        "summary": summary,
        "diagnostics": warnings,
        "unresolved_imports": [],
        "contracts": [_contract_to_dict(c) for c in contracts],
        "ecosystem": ecosystem,
    }


def _contract_to_dict(c: Contract) -> dict:
    d = asdict(c)
    d["deployable"] = c.is_deployable and not c.test_helper
    return d


def describe_backend(blueprint: dict) -> str:
    comp = blueprint.get("compiler") or {}
    return "ast/" + " ".join(x for x in (comp.get("driver"), comp.get("version")) if x)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

CONFIG_FILE = "foundryguard.toml"


def load_config(root: Path, path: str | None = None) -> dict:
    """Load ``foundryguard.toml`` (or ``path``). Missing file -> empty config."""
    cfg_path = Path(path) if path else root / CONFIG_FILE
    if not cfg_path.is_file():
        if path:
            raise SystemExit(f"foundryguard: config not found: {cfg_path}")
        return {}
    return compiler._toml(cfg_path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def add_scan_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("paths", nargs="*", help="source dirs or .sol files, relative to --root (default: src/ or contracts/)")
    ap.add_argument("--root", default=".", help="project root containing foundry.toml (default: .)")
    ap.add_argument("--config", help=f"config file (default: <root>/{CONFIG_FILE} if present)")
    ap.add_argument("--compiler", choices=compiler.COMPILERS, default="auto",
                    help="auto: native solc (svm / solc-select cache, PATH), then solcjs, then forge (default: auto)")
    ap.add_argument("--solc", help=f"solc or solcjs binary to use (also ${compiler.ENV_SOLC})")
    ap.add_argument("--ast", dest="ast_path", help="read an existing AST instead of compiling: forge out/ dir, "
                    "build-info file or saved Standard JSON output")
    ap.add_argument("--save-ast", help="also write the compiler's AST (Standard JSON sources) to this file")
    ap.add_argument("--build-dir", default="out", help="forge build output dir, relative to root (default: out)")
    ap.add_argument("--no-build", action="store_true", help="do not compile; read the AST from --build-dir")
    ap.add_argument("--backend", choices=("ast", "auto", "regex"), default="ast", help=argparse.SUPPRESS)


def scan_from_args(args: argparse.Namespace) -> dict:
    if getattr(args, "backend", "ast") == "regex":
        raise SystemExit("foundryguard: the regex backend was removed in 0.4; the parser reads the solc AST only")
    root = Path(args.root)
    config = load_config(root.resolve(), args.config)
    paths = args.paths or list(config.get("scan", {}).get("paths", []))
    return build_blueprint(root, paths, config=config, compiler_kind=args.compiler, solc=args.solc,
                           ast_path=args.ast_path, build_dir=args.build_dir, run_build=not args.no_build,
                           save_ast=args.save_ast)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="foundryguard-parse",
        description="Compile Solidity sources and map deposit / withdraw / staking-lock functions from the solc AST.",
    )
    add_scan_args(ap)
    ap.add_argument("-o", "--output", default="foundryguard.json", help="blueprint path, or '-' for stdout (default: foundryguard.json)")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.WARNING - 10 * min(args.verbose, 2), format="%(levelname)s %(name)s: %(message)s")
    blueprint = scan_from_args(args)
    payload = json.dumps(blueprint, indent=2, sort_keys=False) + "\n"

    if args.output == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload)
        s = blueprint["summary"]
        print(
            f"foundryguard: {s['contracts']} contract(s) in {s['files_scanned']} file(s) [{describe_backend(blueprint)}] "
            f"-> {out} [deposit={s['deposit_functions']} withdraw={s['withdraw_functions']} stake_lock={s['stake_lock_functions']}"
            f" ecosystems={s['ecosystems']}]",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
