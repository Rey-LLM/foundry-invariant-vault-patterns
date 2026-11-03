#!/usr/bin/env python3
"""FoundryGuard parser: scan Solidity sources and emit a structural JSON blueprint.

The parser walks standard Foundry/Hardhat source directories, strips comments,
splits every file into its contract / abstract contract / interface / library
blocks, and extracts each function signature (parameters, visibility, state
mutability, modifiers and return values). Every function is then classified
against the value-flow categories FoundryGuard generates invariants for:

* ``deposit``   - value entering the system (deposit, mint, supply, ...)
* ``withdraw``  - value leaving the system (withdraw, redeem, exit, ...)
* ``stake_lock`` - staking and time-lock flows (stake, unstake, lock, claim, ...)

Function bodies are also scanned for external hook callbacks (Uniswap v4 ``beforeSwap`` /
``afterSwap`` style hooks, ``unlockCallback`` on ``msg.sender``, ``*Callback``, ``onFlashLoan``); a
contract that makes them is flagged with ``hooks`` so the injector adds the Preset 04
read-reentrancy checks (``blueprints/hook_reentrancy.py``).

Imports are followed (using ``foundry.toml`` / ``remappings.txt`` remappings) so
that functions inherited from parent contracts in libraries such as
OpenZeppelin can be resolved by the injector, without making those library
contracts test targets themselves.

Usage::

    python3 src/cli/parser.py                     # scan ./src (or ./contracts)
    python3 src/cli/parser.py src contracts -o foundryguard.json
    python3 src/cli/parser.py --root path/to/project --no-follow-imports

The output is a deterministic JSON document (``schema: foundryguard.blueprint/v1``)
consumed by ``injector.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

if __package__:
    from .blueprints import hook_reentrancy
else:  # executed as a plain script directory (python3 src/cli/parser.py)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from blueprints import hook_reentrancy  # type: ignore

SCHEMA = "foundryguard.blueprint/v1"
TOOL_VERSION = "0.3.0"

log = logging.getLogger("foundryguard.parser")

# Directories FoundryGuard scans when no path is given, in priority order.
DEFAULT_SOURCE_DIRS = ("src", "contracts")
# Directories never scanned as targets (dependencies, build output, tests).
EXCLUDED_DIRS = {"lib", "node_modules", "out", "cache", "artifacts", "broadcast", ".git", "test", "tests", "script"}

# --------------------------------------------------------------------------- #
# Classification rules
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

VISIBILITIES = {"public", "external", "internal", "private"}
MUTABILITIES = {"pure", "view", "payable", "nonpayable"}
DATA_LOCATIONS = {"memory", "storage", "calldata"}
HEADER_KEYWORDS = VISIBILITIES | MUTABILITIES | {"virtual"}

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Param:
    type: str
    name: str
    location: str | None = None

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
    mutability: str
    modifiers: list[str]
    virtual: bool
    override: bool
    has_body: bool
    line: int
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
    inherits: list[str]
    functions: list[Function] = field(default_factory=list)
    constructor: Function | None = None
    accounting_getters: list[str] = field(default_factory=list)
    state_vars: list[dict] = field(default_factory=list)  # public state variables: {name, type}
    categories: dict[str, list[str]] = field(default_factory=dict)
    external: bool = False
    test_helper: bool = False
    hooks: dict = field(default_factory=dict)  # {"callbacks": [...], "call_sites": [...]} when it calls hooks

    @property
    def is_deployable(self) -> bool:
        return self.kind == "contract"


# --------------------------------------------------------------------------- #
# Lexing helpers
# --------------------------------------------------------------------------- #


def strip_comments(source: str) -> str:
    """Remove // and /* */ comments while keeping string literals and line numbers intact."""
    out: list[str] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if c in "\"'":
            # Copy the string literal verbatim, honouring escapes.
            j = i + 1
            while j < n and source[j] != c:
                j += 2 if source[j] == "\\" else 1
            out.append(source[i : j + 1])
            i = j + 1
        elif c == "/" and nxt == "/":
            j = source.find("\n", i)
            i = n if j == -1 else j
        elif c == "/" and nxt == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            # Preserve newlines so reported line numbers stay accurate.
            out.append("\n" * source.count("\n", i, j))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def mask_strings(text: str) -> str:
    """Blank out string-literal contents (keeping the quotes) so structural regexes ignore them."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            inner = text[i + 1 : min(j, n)]
            out.append(c + re.sub(r"[^\n]", " ", inner) + (c if j < n else ""))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def match_bracket(text: str, start: int, open_ch: str = "(", close_ch: str = ")") -> int:
    """Return the index of the bracket closing the one at ``start`` (skipping strings)."""
    depth = 0
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"unbalanced '{open_ch}' at offset {start}")


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split on ``sep`` ignoring separators nested inside (), [] or {}."""
    parts, depth, cur = [], 0, []
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def normalize_type(raw: str) -> str:
    """Canonicalise elementary type aliases (uint -> uint256, etc.)."""
    t = re.sub(r"\s+", " ", raw.strip())
    t = re.sub(r"\baddress payable\b", "address", t)
    t = re.sub(r"\buint\b(?!\d)", "uint256", t)
    t = re.sub(r"\bint\b(?!\d)", "int256", t)
    t = re.sub(r"\bbyte\b", "bytes1", t)
    return t.replace(" [", "[")


def parse_params(text: str) -> list[Param]:
    params: list[Param] = []
    for idx, chunk in enumerate(split_top_level(text)):
        if not chunk:
            continue
        chunk = re.sub(r"\baddress\s+payable\b", "address", chunk)
        tokens = chunk.split()
        location = None
        name = ""
        if tokens and tokens[-1] not in DATA_LOCATIONS and len(tokens) > 1 and re.fullmatch(r"[A-Za-z_$][\w$]*", tokens[-1]):
            name = tokens.pop()
        if tokens and tokens[-1] in DATA_LOCATIONS:
            location = tokens.pop()
        tokens = [t for t in tokens if t not in {"indexed"}]
        ptype = normalize_type(" ".join(tokens))
        params.append(Param(type=ptype, name=name or f"arg{idx}", location=location))
    return params


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r"""import\s+(?:[^'"]*?\bfrom\s+)?["']([^"']+)["']\s*;""")
CONTRACT_RE = re.compile(r"\b(abstract\s+contract|contract|interface|library)\s+([A-Za-z_$][\w$]*)\s*(?:is\s+([^{]+))?\{")
FUNC_RE = re.compile(r"\b(function\s+([A-Za-z_$][\w$]*)|constructor|fallback|receive)\s*\(")


def parse_inheritance(text: str | None) -> list[str]:
    if not text:
        return []
    parents = []
    for chunk in split_top_level(text):
        m = re.match(r"([A-Za-z_$][\w$.]*)", chunk.strip())
        if m:
            parents.append(m.group(1).split(".")[-1])
    return parents


def parse_header(header: str, kind: str, in_interface: bool) -> dict:
    """Parse the text between a function's parameter list and its body/semicolon."""
    returns: list[Param] = []
    m = re.search(r"\breturns\s*\(", header)
    if m:
        open_idx = m.end() - 1
        close_idx = match_bracket(header, open_idx)
        returns = parse_params(header[open_idx + 1 : close_idx])
        header = header[: m.start()] + " " + header[close_idx + 1 :]

    override = bool(re.search(r"\boverride\b", header))
    header = re.sub(r"\boverride\s*(\([^)]*\))?", " ", header)

    visibility = None
    mutability = "nonpayable"
    virtual = False
    modifiers: list[str] = []
    for tok in re.finditer(r"([A-Za-z_$][\w$.]*)\s*(\((?:[^()]|\([^()]*\))*\))?", header):
        word = tok.group(1)
        if word in VISIBILITIES:
            visibility = word
        elif word in MUTABILITIES:
            mutability = word
        elif word == "virtual":
            virtual = True
        else:
            modifiers.append(word)

    if visibility is None:
        if kind in {"fallback", "receive"} or in_interface:
            visibility = "external"
        elif kind == "constructor":
            visibility = "public"
        else:
            visibility = "public"  # pre-0.5 default; modern solc requires it explicitly
    if kind == "receive":
        mutability = "payable"
    return dict(returns=returns, visibility=visibility, mutability=mutability,
                virtual=virtual, override=override, modifiers=modifiers)


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
    for p in fn.params:
        if re.fullmatch(r"uint\d*", p.type) and AMOUNT_PARAM.match(p.name):
            fn.amount_param = p.name
            break
    else:
        uints = [p for p in fn.params if re.fullmatch(r"uint\d*", p.type)]
        if len(uints) == 1:
            fn.amount_param = uints[0].name
    if fn.amount_param:
        fn.unit = "shares" if SHARE_PARAM.search(fn.amount_param) else "assets"
    elif fn.mutability == "payable" and fn.direction == "in":
        fn.amount_param, fn.unit = "msg.value", "native"


def extract_contracts(source: str, rel_path: str, rules=CLASSIFICATION_RULES) -> tuple[list[Contract], list[str]]:
    stripped = strip_comments(source)
    imports = IMPORT_RE.findall(stripped)
    text = mask_strings(stripped)
    pragma_m = PRAGMA_RE.search(text)
    pragma = pragma_m.group(1).strip() if pragma_m else None
    # Files that import forge-std are fixtures/handlers living under src/, not protocol code.
    test_helper = any(i.startswith(("forge-std/", "ds-test/")) for i in imports)

    contracts: list[Contract] = []
    for m in CONTRACT_RE.finditer(text):
        kind = re.sub(r"\s+", " ", m.group(1))
        body_open = m.end() - 1
        try:
            body_close = match_bracket(text, body_open, "{", "}")
        except ValueError:
            log.warning("%s: unbalanced braces in %s, skipping", rel_path, m.group(2))
            continue
        contract = Contract(
            name=m.group(2), kind=kind, file=rel_path, line=line_of(text, m.start()),
            pragma=pragma, inherits=parse_inheritance(m.group(3)), test_helper=test_helper,
        )
        body = text[body_open + 1 : body_close]
        body_offset = body_open + 1
        pos = 0
        while True:
            fm = FUNC_RE.search(body, pos)
            if not fm:
                break
            if fm.group(2):
                fkind, fname = "function", fm.group(2)
            else:
                fkind = fm.group(1)
                fname = fkind
            p_open = fm.end() - 1
            try:
                p_close = match_bracket(body, p_open)
            except ValueError:
                log.warning("%s: cannot parse parameters of %s.%s, skipping", rel_path, contract.name, fname)
                pos = fm.end()
                continue
            params = parse_params(body[p_open + 1 : p_close])
            # Header runs to the first top-level '{' or ';'.
            j, depth = p_close + 1, 0
            while j < len(body):
                ch = body[j]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif depth == 0 and ch in "{;":
                    break
                j += 1
            header = parse_header(body[p_close + 1 : j], fkind, kind == "interface")
            has_body = j < len(body) and body[j] == "{"
            signature = f"{fname}({','.join(p.type for p in params)})"
            fn = Function(
                name=fname, kind=fkind, signature=signature, params=params,
                line=line_of(text, body_offset + fm.start()), has_body=has_body, **header,
            )
            classify(fn, rules)
            if fkind == "constructor":
                contract.constructor = fn
            else:
                contract.functions.append(fn)
            try:
                body_end = match_bracket(body, j, "{", "}") if has_body else j
            except ValueError:
                log.warning("%s: unbalanced body in %s.%s", rel_path, contract.name, fname)
                break
            if has_body:
                fn.callbacks = hook_reentrancy.detect_callbacks(body[j + 1 : body_end])
            pos = body_end + 1

        # Public state variables expose implicit getters (e.g. `uint256 public totalStaked`).
        for vm_ in re.finditer(
            r"^\s*(mapping\s*\(.+?\)|[A-Za-z_$][\w$.\[\]]*)\s+(?:(?:public|immutable|constant|override)\s+)*public\s+(?:(?:immutable|constant|override)\s+)*([A-Za-z_$][\w$]*)\s*[;=]",
            _strip_nested_blocks(body), re.M,
        ):
            contract.state_vars.append({"name": vm_.group(2), "type": normalize_type(vm_.group(1))})
            if vm_.group(2) in ACCOUNTING_GETTERS:
                contract.accounting_getters.append(vm_.group(2))
        for fn in contract.functions:
            if fn.name in ACCOUNTING_GETTERS and fn.mutability in {"view", "pure"} and fn.visibility in {"public", "external"}:
                contract.accounting_getters.append(fn.name)
        contract.accounting_getters = sorted(set(contract.accounting_getters))
        contracts.append(contract)
    return contracts, imports


def _strip_nested_blocks(body: str) -> str:
    """Return the contract body with every nested {...} block blanked out."""
    out, depth = [], 0
    for c in body:
        if c == "{":
            depth += 1
            continue
        if c == "}":
            depth -= 1
            continue
        out.append(c if depth == 0 else ("\n" if c == "\n" else " "))
    return "".join(out)


# --------------------------------------------------------------------------- #
# Project discovery
# --------------------------------------------------------------------------- #


def load_remappings(root: Path) -> list[tuple[str, str]]:
    """Read remappings from remappings.txt and foundry.toml ([profile.default])."""
    remaps: list[tuple[str, str]] = []
    txt = root / "remappings.txt"
    if txt.is_file():
        for line in txt.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                remaps.append((k.split(":")[-1], v))
    toml = root / "foundry.toml"
    if toml.is_file():
        m = re.search(r"remappings\s*=\s*\[(.*?)\]", toml.read_text(), re.S)
        if m:
            for entry in re.findall(r"""["']([^"']+)["']""", m.group(1)):
                if "=" in entry:
                    k, v = entry.split("=", 1)
                    remaps.append((k.split(":")[-1], v))
    # Longest prefix first, as solc does.
    return sorted(remaps, key=lambda kv: len(kv[0]), reverse=True)


def resolve_import(root: Path, importer: Path, path: str, remaps: list[tuple[str, str]]) -> Path | None:
    if path.startswith("."):
        cand = (importer.parent / path).resolve()
        return cand if cand.is_file() else None
    for prefix, target in remaps:
        if path.startswith(prefix):
            cand = (root / (target + path[len(prefix):])).resolve()
            if cand.is_file():
                return cand
    for base in (root, root / "lib", root / "node_modules"):
        cand = (base / path).resolve()
        if cand.is_file():
            return cand
    return None


def discover_sources(root: Path, paths: Iterable[str]) -> list[Path]:
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
    return sorted(files)


def rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def build_blueprint(root: Path, paths: list[str], follow_imports: bool = True, backend: str = "auto",
                    config: dict | None = None, build_dir: str = "out", run_build: bool = True) -> dict:
    """Scan the project and return the blueprint dict.

    ``backend``: ``regex`` (no compiler needed), ``ast`` (solc AST from forge build output, error if
    missing) or ``auto`` (AST when available, regex otherwise).
    """
    root = root.resolve()
    rules = build_rules(config)
    if backend in ("auto", "ast"):
        try:
            from_ast = _ast_backend()
        except ImportError:  # pragma: no cover - module ships with the package
            from_ast = None
        if from_ast is not None:
            result = from_ast.build_from_ast(root, paths, rules=rules, build_dir=build_dir,
                                             run_build=run_build, required=(backend == "ast"))
            if result is not None:
                contracts, files_scanned, unresolved = result
                return _finish_blueprint(root, paths, load_remappings(root), contracts, files_scanned,
                                         unresolved, "ast")
        if backend == "ast":
            raise SystemExit("foundryguard: --backend ast requested but no solc AST was found (run `forge build --ast`)")
    remaps = load_remappings(root)
    queue = [(p, False) for p in discover_sources(root, paths)]
    seen: set[Path] = set()
    contracts: list[Contract] = []
    unresolved: set[str] = set()
    files_scanned = 0

    while queue:
        path, external = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            log.warning("cannot read %s: %s", path, exc)
            continue
        files_scanned += 1
        found, imports = extract_contracts(source, rel(root, path), rules)
        for c in found:
            c.external = external
        contracts.extend(found)
        log.debug("%s: %d contract(s)", rel(root, path), len(found))
        if follow_imports:
            for imp in imports:
                resolved = resolve_import(root, path, imp, remaps)
                if resolved is None:
                    unresolved.add(imp)
                elif resolved not in seen:
                    queue.append((resolved, external or not _is_under(resolved, root, paths)))

    return _finish_blueprint(root, paths, remaps, contracts, files_scanned, unresolved, "regex")


def _ast_backend():
    if __package__:
        from . import ast_backend  # type: ignore
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import ast_backend  # type: ignore
    return ast_backend


def _finish_blueprint(root: Path, paths: list[str], remaps, contracts: list[Contract], files_scanned: int,
                      unresolved: set[str], backend: str) -> dict:
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
    targets = [c for c in contracts if not c.external and not c.test_helper]
    summary = {
        "files_scanned": files_scanned,
        "contracts": len(targets),
        "external_contracts": sum(1 for c in contracts if c.external),
        "test_helpers": sum(1 for c in contracts if c.test_helper and not c.external),
        "deposit_functions": sum(len(c.categories.get("deposit", [])) for c in targets),
        "withdraw_functions": sum(len(c.categories.get("withdraw", [])) for c in targets),
        "stake_lock_functions": sum(len(c.categories.get("stake_lock", [])) for c in targets),
        "hook_contracts": sum(1 for c in targets if c.hooks),
    }
    return {
        "schema": SCHEMA,
        "tool": {"name": "foundryguard", "version": TOOL_VERSION},
        "backend": backend,
        "root": root.as_posix(),
        "source_paths": list(paths) or [d for d in DEFAULT_SOURCE_DIRS if (root / d).is_dir()],
        "remappings": [f"{k}={v}" for k, v in remaps],
        "summary": summary,
        "unresolved_imports": sorted(unresolved),
        "contracts": [_contract_to_dict(c) for c in contracts],
    }


def _is_under(path: Path, root: Path, paths: list[str]) -> bool:
    bases = [root / p for p in paths] if paths else [root / d for d in DEFAULT_SOURCE_DIRS]
    for b in bases:
        b = b.resolve()
        if path == b or b in path.parents:
            return not any(part in EXCLUDED_DIRS for part in path.relative_to(b).parts[:-1])
    return False


def _contract_to_dict(c: Contract) -> dict:
    d = asdict(c)
    d["deployable"] = c.is_deployable and not c.test_helper
    return d


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
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover
        try:
            import tomli as tomllib  # type: ignore
        except ModuleNotFoundError:
            raise SystemExit("foundryguard: reading foundryguard.toml needs Python 3.11+ or `pip install tomli`")
    try:
        return tomllib.loads(cfg_path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"foundryguard: {cfg_path} is not valid TOML: {exc}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def add_scan_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("paths", nargs="*", help="source dirs or .sol files, relative to --root (default: src/ or contracts/)")
    ap.add_argument("--root", default=".", help="project root containing foundry.toml (default: .)")
    ap.add_argument("--config", help=f"config file (default: <root>/{CONFIG_FILE} if present)")
    ap.add_argument("--backend", choices=("auto", "ast", "regex"), default="auto",
                    help="auto: solc AST from forge build output when available, else regex (default: auto)")
    ap.add_argument("--build-dir", default="out", help="forge build output dir, relative to root (default: out)")
    ap.add_argument("--no-build", action="store_true", help="never run `forge build --ast`; only read existing output")
    ap.add_argument("--no-follow-imports", action="store_true", help="regex backend: do not parse imported files")


def scan_from_args(args: argparse.Namespace) -> dict:
    root = Path(args.root)
    config = load_config(root.resolve(), args.config)
    paths = args.paths or list(config.get("scan", {}).get("paths", []))
    return build_blueprint(root, paths, follow_imports=not args.no_follow_imports, backend=args.backend,
                           config=config, build_dir=args.build_dir, run_build=not args.no_build)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="foundryguard-parse",
        description="Scan Solidity sources and map deposit / withdraw / staking-lock functions into a JSON blueprint.",
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
            f"foundryguard: {s['contracts']} contract(s) in {s['files_scanned']} file(s) [{blueprint['backend']}] -> {out} "
            f"[deposit={s['deposit_functions']} withdraw={s['withdraw_functions']} stake_lock={s['stake_lock_functions']}]",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
