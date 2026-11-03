#!/usr/bin/env python3
"""FoundryGuard AST backend: build the blueprint from the solc AST instead of regexes.

The compiler's AST is exact: inheritance, overloads, user-defined types, free
functions and odd formatting are all resolved by solc itself. The backend reads
any of these JSON layouts, so it works with plain Foundry, Hardhat or solc:

* Foundry artifacts written with ``forge build --ast`` (``out/<File>.sol/<C>.json``,
  top-level ``"ast"`` key)
* Foundry / Hardhat build-info files (``out/build-info/*.json``,
  ``output.sources.<path>.ast``)
* raw ``solc --standard-json`` output (``sources.<path>.ast``)

When ``run_build`` is set and ``forge`` is on ``PATH``, ``forge build --ast`` is
run first so the AST is fresh. If no AST can be found the caller falls back to
the regex parser (``--backend auto``) or stops (``--backend ast``).
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path

if __package__:
    from .blueprints import hook_reentrancy
    from .parser import (DEFAULT_SOURCE_DIRS, EXCLUDED_DIRS, ACCOUNTING_GETTERS, CLASSIFICATION_RULES,
                         Contract, Function, Param, classify, normalize_type)
else:  # executed as a plain script directory (python3 src/cli/foundryguard.py)
    from blueprints import hook_reentrancy  # type: ignore
    from parser import (DEFAULT_SOURCE_DIRS, EXCLUDED_DIRS, ACCOUNTING_GETTERS, CLASSIFICATION_RULES,  # type: ignore
                        Contract, Function, Param, classify, normalize_type)

log = logging.getLogger("foundryguard.ast")


def run_forge_build(root: Path, build_dir: str) -> bool:
    forge = shutil.which("forge")
    if not forge:
        return False
    cmd = [forge, "build", "--ast", "--root", str(root), "--out", build_dir]
    log.info("running %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("forge build failed to run: %s", exc)
        return False
    if proc.returncode != 0:
        log.warning("forge build --ast failed, falling back to the regex parser:\n%s", (proc.stderr or proc.stdout)[-2000:])
        return False
    return True


def collect_asts(build_path: Path) -> dict[str, dict]:
    """Map absolutePath -> SourceUnit AST from every JSON file under ``build_path``."""
    units: dict[str, dict] = {}
    if not build_path.exists():
        return units
    files = [build_path] if build_path.is_file() else sorted(build_path.rglob("*.json"))
    for f in files:
        try:
            data = json.loads(f.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        candidates = []
        if isinstance(data.get("ast"), dict):
            candidates.append(data["ast"])
        for container in (data.get("output", {}).get("sources", {}) if isinstance(data.get("output"), dict) else {},
                          data.get("sources", {}) if isinstance(data.get("sources"), dict) else {}):
            for src in container.values():
                if isinstance(src, dict) and isinstance(src.get("ast"), dict):
                    candidates.append(src["ast"])
        for ast in candidates:
            if ast.get("nodeType") == "SourceUnit" and ast.get("absolutePath"):
                units.setdefault(ast["absolutePath"], ast)
    return units


_LOCATION = re.compile(r"\s+(memory|calldata|storage)(\s+(pointer|ref|slice))?$")


def ast_type(param: dict) -> str:
    """Turn a VariableDeclaration's typeString into the canonical type the regex parser emits."""
    ts = param.get("typeDescriptions", {}).get("typeString") or ""
    ts = _LOCATION.sub("", ts.strip())
    ts = re.sub(r"\b(contract|struct|enum|library|interface)\s+", "", ts)
    ts = re.sub(r"\s+(memory|calldata|storage)(\s+(pointer|ref|slice))?", "", ts)  # nested arrays
    return normalize_type(ts)


def _line(source: bytes | None, src: str) -> int:
    if not source or not src:
        return 0
    try:
        start = int(src.split(":")[0])
    except ValueError:
        return 0
    return source[:start].count(b"\n") + 1


def _params(node: dict | None) -> list[Param]:
    out = []
    for i, p in enumerate((node or {}).get("parameters", [])):
        loc = p.get("storageLocation")
        out.append(Param(type=ast_type(p), name=p.get("name") or f"arg{i}",
                         location=loc if loc in ("memory", "calldata", "storage") else None))
    return out


def _function(node: dict, source: bytes | None, in_interface: bool, rules) -> Function:
    kind = node.get("kind", "function")
    name = node.get("name") or kind
    params = _params(node.get("parameters"))
    visibility = node.get("visibility") or ("external" if in_interface else "public")
    mods = [m.get("modifierName", {}).get("name", "").split(".")[-1]
            for m in node.get("modifiers", []) if m.get("kind", "modifierInvocation") == "modifierInvocation"]
    fn = Function(
        name=name, kind=kind, signature=f"{name}({','.join(p.type for p in params)})", params=params,
        returns=_params(node.get("returnParameters")), visibility=visibility,
        mutability=node.get("stateMutability", "nonpayable"), modifiers=[m for m in mods if m],
        virtual=bool(node.get("virtual")), override=node.get("overrides") is not None,
        has_body=bool(node.get("implemented")), line=_line(source, node.get("src", "")),
        callbacks=hook_reentrancy.detect_callbacks_ast(node.get("body")),
    )
    classify(fn, rules)
    return fn


def _is_target_path(path: str, paths: list[str], root: Path) -> bool:
    bases = list(paths) or [d for d in DEFAULT_SOURCE_DIRS if (root / d).is_dir()]
    p = Path(path)
    if p.name.endswith((".t.sol", ".s.sol")):
        return False
    for b in bases:
        b = b.rstrip("/")
        if path == b or path.startswith(b + "/"):
            inner = Path(path[len(b) + 1:]).parts[:-1] if path != b else ()
            return not any(part in EXCLUDED_DIRS for part in inner)
    return False


def build_from_ast(root: Path, paths: list[str], rules=CLASSIFICATION_RULES, build_dir: str = "out",
                   run_build: bool = True, required: bool = False):
    """Return ``(contracts, files_scanned, unresolved)`` or ``None`` when no AST is available."""
    build_path = Path(build_dir) if Path(build_dir).is_absolute() else root / build_dir
    built = run_forge_build(root, build_dir) if run_build else False
    units = collect_asts(build_path)
    if not units:
        if required or built:
            log.warning("no solc AST found under %s (forge build --ast writes it)", build_path)
        return None

    contracts: list[Contract] = []
    for path, unit in sorted(units.items()):
        if Path(path).name.endswith((".t.sol", ".s.sol")) or path.startswith(("test/", "script/")):
            continue
        file_path = root / path
        try:
            source = file_path.read_bytes()
        except OSError:
            source = None
        pragma = None
        imports: list[str] = []
        for node in unit.get("nodes", []):
            if node.get("nodeType") == "PragmaDirective" and node.get("literals", [None])[0] == "solidity":
                pragma = ""
                for t in node["literals"][1:]:
                    if t[:1] in "^~<>=|" and pragma and pragma[-1] not in "^~<>=| ":
                        pragma += " "
                    pragma += t
            elif node.get("nodeType") == "ImportDirective":
                imports.append(node.get("file", ""))
        test_helper = any(i.startswith(("forge-std/", "ds-test/")) for i in imports)
        external = not _is_target_path(path, paths, root)
        for node in unit.get("nodes", []):
            if node.get("nodeType") != "ContractDefinition":
                continue
            ck = node.get("contractKind", "contract")
            kind = "abstract contract" if (ck == "contract" and node.get("abstract")) else ck
            c = Contract(
                name=node["name"], kind=kind, file=path, line=_line(source, node.get("src", "")), pragma=pragma,
                inherits=[(b.get("baseName", {}).get("name") or b.get("baseName", {}).get("namePath", "")).split(".")[-1]
                          for b in node.get("baseContracts", [])],
                external=external, test_helper=test_helper,
            )
            for member in node.get("nodes", []):
                nt = member.get("nodeType")
                if nt == "FunctionDefinition":
                    fn = _function(member, source, ck == "interface", rules)
                    if fn.kind == "constructor":
                        c.constructor = fn
                    else:
                        c.functions.append(fn)
                        if (fn.name in ACCOUNTING_GETTERS and fn.mutability in ("view", "pure")
                                and fn.visibility in ("public", "external")):
                            c.accounting_getters.append(fn.name)
                elif nt == "VariableDeclaration" and member.get("stateVariable") and member.get("visibility") == "public":
                    c.state_vars.append({"name": member["name"], "type": ast_type(member)})
                    if member["name"] in ACCOUNTING_GETTERS:
                        c.accounting_getters.append(member["name"])
            c.accounting_getters = sorted(set(c.accounting_getters))
            contracts.append(c)
    return contracts, len(units), set()
