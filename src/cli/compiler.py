#!/usr/bin/env python3
"""FoundryGuard compiler driver: get a solc compact-JSON AST for a project.

The parser never reads Solidity text itself. It asks the compiler for the AST and
works on that, so formatting, comments, overloads, inheritance and imports are
resolved exactly the way solc resolves them.

Drivers, tried in this order by ``--compiler auto``:

``solc``
    A native solc: ``--solc PATH`` / ``$FOUNDRYGUARD_SOLC``, then the binaries
    Foundry (svm) and solc-select keep in their caches, then ``solc`` on ``PATH``.
``solcjs``
    The npm build (``npm install solc``), slower but needs nothing else.
``forge``
    ``forge build --ast`` and the AST from the build output.

The ``solc`` and ``solcjs`` drivers use Standard JSON in two passes:

1. ``stopAfter: "parsing"`` - only the parser runs, so a syntax error anywhere in
   the project (or a missing import) is reported at once, with file:line:col,
   before any type checking;
2. the full analysis, which yields the typed AST (``typeDescriptions``,
   ``referencedDeclaration``, ``linearizedBaseContracts``, selectors).

Compiler errors stop the scan with a ``SolidityError`` that lists every
diagnostic. ``read_prebuilt`` loads an AST that was produced elsewhere (forge
``out/``, Hardhat / forge build-info, or saved Standard JSON output).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("foundryguard.compiler")

COMPILERS = ("auto", "solc", "solcjs", "forge")
ENV_SOLC = "FOUNDRYGUARD_SOLC"
COMPILE_TIMEOUT = 900


# --------------------------------------------------------------------------- #
# Diagnostics
# --------------------------------------------------------------------------- #


@dataclass
class Diagnostic:
    severity: str            # error | warning | info
    type: str                # ParserError, SyntaxError, DeclarationError, TypeError, ...
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None

    def __str__(self) -> str:
        where = self.file or "<project>"
        if self.line:
            where += f":{self.line}:{self.column or 1}"
        return f"{where}: {self.type}: {self.message}"

    def as_dict(self) -> dict:
        return {"severity": self.severity, "type": self.type, "message": self.message,
                "file": self.file, "line": self.line, "column": self.column}


class SolidityError(SystemExit):
    """The sources do not compile (or the AST is unusable). Carries every diagnostic."""

    def __init__(self, headline: str, diagnostics: list[Diagnostic] | None = None, hint: str | None = None):
        self.headline = headline
        self.diagnostics = list(diagnostics or [])
        self.hint = hint
        lines = [f"foundryguard: {headline}"]
        lines += [f"  {d}" for d in self.diagnostics]
        if hint:
            lines.append(f"  hint: {hint}")
        super().__init__("\n".join(lines))


# --------------------------------------------------------------------------- #
# Versions and pragmas
# --------------------------------------------------------------------------- #


def parse_version(text: str) -> tuple[int, int, int]:
    nums = []
    for part in text.strip().lstrip("v").split("+")[0].split("-")[0].split("."):
        if not part.isdigit():
            break
        nums.append(int(part))
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def _comparators(alternative: str) -> list[tuple[str, str]]:
    tokens = alternative.replace(" - ", " -range- ").split()
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if i + 2 < len(tokens) and tokens[i + 1] == "-range-":
            out += [(">=", tok), ("<=", tokens[i + 2])]
            i += 3
            continue
        op = next((o for o in (">=", "<=", "^", "~", ">", "<", "=") if tok.startswith(o)), "")
        rest = tok[len(op):]
        if not rest and i + 1 < len(tokens):  # "^ 0.8.20" as solc literals come apart
            rest = tokens[i + 1]
            i += 1
        out.append((op or "=", rest))
        i += 1
    return out


def satisfies(version: str, pragma: str | None) -> bool:
    """True if ``version`` (e.g. ``0.8.24``) meets a ``pragma solidity`` expression."""
    if not pragma:
        return True
    v = parse_version(version)
    for alternative in pragma.split("||"):
        ok = True
        for op, ref in _comparators(alternative):
            r = parse_version(ref)
            if op == "^":
                upper = (r[0] + 1, 0, 0) if r[0] else ((0, r[1] + 1, 0) if r[1] else (0, 0, r[2] + 1))
                ok = r <= v < upper
            elif op == "~":
                ok = r <= v < (r[0], r[1] + 1, 0)
            elif op == ">=":
                ok = v >= r
            elif op == "<=":
                ok = v <= r
            elif op == ">":
                ok = v > r
            elif op == "<":
                ok = v < r
            else:
                ok = v == r
            if not ok:
                break
        if ok:
            return True
    return False


# --------------------------------------------------------------------------- #
# Project settings
# --------------------------------------------------------------------------- #


def _toml(path: Path) -> dict:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover
        try:
            import tomli as tomllib  # type: ignore
        except ModuleNotFoundError:
            raise SystemExit("foundryguard: reading foundry.toml needs Python 3.11+ or `pip install tomli`")
    try:
        return tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"foundryguard: {path} is not valid TOML: {exc}")


def foundry_profile(root: Path) -> dict:
    """``[profile.default]`` merged with ``[profile.$FOUNDRY_PROFILE]`` from foundry.toml."""
    path = root / "foundry.toml"
    if not path.is_file():
        return {}
    profiles = _toml(path).get("profile", {})
    merged = dict(profiles.get("default", {}))
    name = os.environ.get("FOUNDRY_PROFILE")
    if name and name != "default":
        merged.update(profiles.get(name, {}))
    return merged


def _split_remapping(entry: str) -> tuple[str, str, str] | None:
    entry = entry.strip()
    if not entry or entry.startswith("#") or "=" not in entry:
        return None
    left, target = entry.split("=", 1)
    context, _, prefix = left.rpartition(":")
    return context, prefix, target


def load_remappings(root: Path) -> list[str]:
    """Remappings from remappings.txt, foundry.toml, ``forge remappings`` and lib/ auto-detection.

    Earlier sources win for the same (context, prefix). Returned in solc's ``context:prefix=target`` form.
    """
    entries: list[str] = []
    txt = root / "remappings.txt"
    if txt.is_file():
        entries += txt.read_text().splitlines()
    entries += [str(e) for e in foundry_profile(root).get("remappings", [])]
    forge = shutil.which("forge")
    if forge and (root / "foundry.toml").is_file():
        try:
            proc = subprocess.run([forge, "remappings", "--root", str(root)], capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                entries += proc.stdout.splitlines()
        except (OSError, subprocess.TimeoutExpired):
            pass
    entries += _auto_lib_remappings(root)

    seen: set[tuple[str, str]] = set()
    out: list[str] = []
    for e in entries:
        parts = _split_remapping(e)
        if not parts:
            continue
        context, prefix, target = parts
        if (context, prefix) in seen:
            continue
        seen.add((context, prefix))
        out.append(f"{context + ':' if context else ''}{prefix}={target}")
    return out


def _auto_lib_remappings(root: Path) -> list[str]:
    """What forge would infer for the usual lib/ layouts when nothing is configured."""
    out: list[str] = []
    for libs_dir in [str(d) for d in foundry_profile(root).get("libs", [])] or ["lib"]:
        base = root / libs_dir
        if not base.is_dir() or base.name == "node_modules":  # packages resolve through --include-path
            continue
        for dep in sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith((".", "@"))):
            rel = dep.relative_to(root).as_posix()
            if dep.name == "openzeppelin-contracts" and (dep / "contracts").is_dir():
                out.append(f"@openzeppelin/contracts/={rel}/contracts/")
            elif dep.name == "openzeppelin-contracts-upgradeable" and (dep / "contracts").is_dir():
                out.append(f"@openzeppelin/contracts-upgradeable/={rel}/contracts/")
            for sub in ("src", "contracts"):
                if (dep / sub).is_dir():
                    out.append(f"{dep.name}/={rel}/{sub}/")
                    break
    return out


# --------------------------------------------------------------------------- #
# Compiler discovery
# --------------------------------------------------------------------------- #


@dataclass
class Compiler:
    kind: str       # solc | solcjs
    path: str
    version: str

    def __str__(self) -> str:
        return f"{self.kind} {self.version}"


def _probe_version(path: str) -> str | None:
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", proc.stdout + proc.stderr)
    return m.group(1) if m else None


def _cached_solc_binaries() -> list[tuple[str, str]]:
    """(version, path) for solc builds kept by Foundry's svm and by solc-select."""
    home = Path.home()
    found: list[tuple[str, str]] = []
    roots = [Path(os.environ["SVM_HOME"])] if os.environ.get("SVM_HOME") else []
    roots += [home / ".svm", home / ".foundry" / "svm", home / ".local" / "share" / "svm"]
    for svm in roots:
        if svm.is_dir():
            for d in svm.iterdir():
                b = d / f"solc-{d.name}"
                if b.is_file() and os.access(b, os.X_OK):
                    found.append((d.name, str(b)))
    artifacts = home / ".solc-select" / "artifacts"
    if artifacts.is_dir():
        for d in artifacts.iterdir():
            b = d / d.name
            if d.name.startswith("solc-") and b.is_file() and os.access(b, os.X_OK):
                found.append((d.name[len("solc-"):], str(b)))
    return found


def discover_compilers(kind: str = "auto", explicit: str | None = None) -> list[Compiler]:
    """Every solc / solcjs this machine has, the explicit one first."""
    out: list[Compiler] = []
    seen: set[str] = set()

    def add(k: str, path: str | None, version: str | None = None) -> None:
        if not path or path in seen:
            return
        version = version or _probe_version(path)
        if version:
            seen.add(path)
            out.append(Compiler(k, path, version))

    explicit = explicit or os.environ.get(ENV_SOLC)
    if explicit:
        resolved = shutil.which(explicit) or explicit
        if not Path(resolved).is_file():
            raise SystemExit(f"foundryguard: compiler not found: {explicit}")
        add("solcjs" if Path(resolved).name.startswith("solcjs") else "solc", resolved)
        if not out:
            raise SystemExit(f"foundryguard: {explicit} does not answer `--version`; is it a solc binary?")
        return out
    if kind in ("auto", "solc"):
        for version, path in sorted(_cached_solc_binaries(), key=lambda vp: parse_version(vp[0]), reverse=True):
            add("solc", path, version)
        add("solc", shutil.which("solc"))
    if kind in ("auto", "solcjs"):
        add("solcjs", shutil.which("solcjs"))
    return out


def order_candidates(compilers: list[Compiler], wanted: str | None) -> list[Compiler]:
    """The pinned version first (foundry.toml ``solc_version``), then newest first, native before solcjs."""
    def key(c: Compiler):
        return (0 if wanted and c.version == wanted else 1, tuple(-x for x in parse_version(c.version)),
                0 if c.kind == "solc" else 1)
    return sorted(compilers, key=key)


# --------------------------------------------------------------------------- #
# Standard JSON compile
# --------------------------------------------------------------------------- #


@dataclass
class CompileResult:
    units: dict[str, dict]                      # source unit name -> SourceUnit AST
    groups: dict[str, str]                      # source unit name -> compile job key (node ids are per job)
    driver: str                                 # solc | solcjs | forge | prebuilt
    version: str | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)  # warnings that did not stop the build
    raw: dict | None = None                     # Standard JSON output (for --save-ast)


def standard_json_input(root: Path, files: list[str], remappings: list[str], parse_only: bool,
                        evm_version: str | None = None) -> dict:
    sources = {}
    for f in files:
        sources[f] = {"content": (root / f).read_text(encoding="utf-8")}
    settings: dict = {"remappings": remappings, "outputSelection": {"*": {"": ["ast"]}}}
    if parse_only:
        settings["stopAfter"] = "parsing"
    if evm_version and not parse_only:
        settings["evmVersion"] = evm_version
    return {"language": "Solidity", "sources": sources, "settings": settings}


def _include_paths(root: Path, remappings: list[str]) -> tuple[list[str], list[str]]:
    include = [str(p) for p in (root / "node_modules",) if p.is_dir()]
    allow = [str(root)] + include
    for r in remappings:
        parts = _split_remapping(r)
        if parts and Path(parts[2]).is_absolute():
            allow.append(parts[2])
    return include, allow


def run_standard_json(compiler: Compiler, root: Path, payload: dict, remappings: list[str]) -> dict:
    include, allow = _include_paths(root, remappings)
    cmd = [compiler.path, "--standard-json", "--base-path", str(root)]
    for p in include:
        cmd += ["--include-path", p]
    if compiler.kind == "solc":
        cmd += ["--allow-paths", ",".join(allow)]
    log.info("running %s", " ".join(cmd))
    # stdin and stdout are files, not pipes: node (solcjs) fails with EAGAIN on a large piped input
    # and can cut output written to a pipe when it exits.
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as inp, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8") as out:
        json.dump(payload, inp)
        inp.flush()
        inp.seek(0)
        try:
            proc = subprocess.run(cmd, stdin=inp, cwd=root, stdout=out, stderr=subprocess.PIPE,
                                  text=True, timeout=COMPILE_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise SolidityError(f"{compiler} did not finish in {COMPILE_TIMEOUT}s")
        except OSError as exc:
            raise SolidityError(f"cannot run {compiler.path}: {exc}")
        out.seek(0)
        text = out.read()
    start = text.find("{")  # solcjs may print notices before the JSON document
    try:
        output = json.loads(text[start:]) if start >= 0 else None
    except json.JSONDecodeError:
        output = None
    if not isinstance(output, dict):
        raise SolidityError(f"{compiler} returned no Standard JSON output (exit code {proc.returncode})",
                            hint=(proc.stderr or text)[-1500:].strip() or None)
    return output


def diagnostics_from(output: dict, root: Path) -> list[Diagnostic]:
    out = []
    for e in output.get("errors", []) or []:
        loc = e.get("sourceLocation") or {}
        file = loc.get("file") or None
        line = col = None
        if file and isinstance(loc.get("start"), int) and loc["start"] >= 0:
            line, col = _line_col(root, file, loc["start"])
        if line is None:
            line, col = _line_col_from_formatted(e.get("formattedMessage") or "", file)
        out.append(Diagnostic(severity=e.get("severity", "error"), type=e.get("type", "Error"),
                              message=(e.get("message") or "").strip(), file=file, line=line, column=col))
    return out


def _line_col(root: Path, file: str, offset: int) -> tuple[int | None, int | None]:
    data = read_source(root, file)
    if data is None:
        return None, None
    head = data[:offset]
    return head.count(b"\n") + 1, offset - (head.rfind(b"\n") + 1) + 1


def _line_col_from_formatted(text: str, file: str | None) -> tuple[int | None, int | None]:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("--> "):
            parts = line[4:].rsplit(":", 3)
            if len(parts) >= 3 and parts[1].isdigit():
                return int(parts[1]), int(parts[2]) if parts[2].isdigit() else None
    return None, None


def read_source(root: Path, unit_name: str) -> bytes | None:
    """Bytes of a source unit as solc saw it (src offsets are byte offsets)."""
    for cand in (root / unit_name, root / "node_modules" / unit_name, Path(unit_name)):
        try:
            if cand.is_file():
                return cand.read_bytes()
        except OSError:
            continue
    return None


VERSION_MISMATCH = "requires different compiler version"


def compile_with_solc(root: Path, files: list[str], compiler: str = "auto", explicit: str | None = None) -> CompileResult:
    """Two-pass Standard JSON compile (parse, then full analysis) with the best available solc."""
    profile = foundry_profile(root)
    wanted = str(profile.get("solc_version") or profile.get("solc") or "") or None
    if wanted and not wanted[:1].isdigit():  # `solc = "/path/to/solc"`
        explicit = explicit or wanted
        wanted = None
    candidates = order_candidates(discover_compilers(compiler, explicit), wanted)
    if not candidates:
        raise SolidityError("no Solidity compiler found",
                            hint="install solc (or `npm install -g solc`), pass --solc PATH, or install Foundry")
    remappings = load_remappings(root)
    evm = profile.get("evm_version")
    last: SolidityError | None = None
    for cand in candidates:
        try:
            return _compile_two_pass(cand, root, files, remappings, evm)
        except SolidityError as exc:
            if exc.diagnostics and all(VERSION_MISMATCH in d.message for d in exc.diagnostics if d.severity == "error"):
                log.info("%s does not satisfy the pragmas, trying the next compiler", cand)
                last = exc
                continue
            raise
    assert last is not None
    raise SolidityError(f"no installed compiler satisfies the pragmas (tried {', '.join(map(str, candidates))})",
                        last.diagnostics, hint="install a matching solc or set solc_version in foundry.toml")


def _compile_two_pass(compiler: Compiler, root: Path, files: list[str], remappings: list[str],
                      evm: str | None) -> CompileResult:
    # Pass 1: parser only. Syntax errors and unresolved imports stop the scan here.
    parsed = run_standard_json(compiler, root, standard_json_input(root, files, remappings, True), remappings)
    diags = diagnostics_from(parsed, root)
    errors = [d for d in diags if d.severity == "error"]
    if errors:
        raise SolidityError(f"{len(errors)} syntax error(s) reported by {compiler}", errors, hint=_hint(errors))
    # Pass 2: full analysis for the typed AST.
    full = run_standard_json(compiler, root, standard_json_input(root, files, remappings, False, evm), remappings)
    diags = diagnostics_from(full, root)
    errors = [d for d in diags if d.severity == "error"]
    if errors:
        raise SolidityError(f"{len(errors)} compiler error(s) reported by {compiler}", errors, hint=_hint(errors))
    units = {name: src["ast"] for name, src in (full.get("sources") or {}).items() if isinstance(src.get("ast"), dict)}
    if not units:
        raise SolidityError(f"{compiler} returned no AST")
    return CompileResult(units=units, groups={n: "standard-json" for n in units}, driver=compiler.kind,
                         version=compiler.version, diagnostics=[d for d in diags if d.severity != "error"], raw=full)


def _hint(errors: list[Diagnostic]) -> str | None:
    if any("not found" in d.message and d.type in ("ParserError", "DeclarationError") for d in errors):
        return "an import did not resolve: install dependencies (`forge install`, `npm install`) or fix remappings"
    if any(VERSION_MISMATCH in d.message for d in errors):
        return "the pragma needs another solc version: set solc_version in foundry.toml or pass --solc"
    return None


# --------------------------------------------------------------------------- #
# forge and prebuilt ASTs
# --------------------------------------------------------------------------- #


def compile_with_forge(root: Path, build_dir: str) -> CompileResult:
    forge = shutil.which("forge")
    if not forge:
        raise SolidityError("--compiler forge needs `forge` on PATH (https://getfoundry.sh)")
    # Build-info files hold whole compile jobs, so node ids in them are consistent even after incremental builds.
    cmd = [forge, "build", "--ast", "--build-info", "--root", str(root), "--out", build_dir]
    log.info("running %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=COMPILE_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SolidityError(f"forge build did not run: {exc}")
    if proc.returncode != 0:
        raise SolidityError("forge build --ast failed", hint=(proc.stderr or proc.stdout)[-3000:].strip())
    result = read_prebuilt(root / build_dir if not Path(build_dir).is_absolute() else Path(build_dir))
    result.driver = "forge"
    return result


def read_prebuilt(path: Path) -> CompileResult:
    """ASTs from forge ``out/`` (``forge build --ast``), build-info files, or saved Standard JSON output."""
    if not path.exists():
        raise SolidityError(f"no AST found at {path}", hint="run `forge build --ast`, or scan with a compiler")
    units: dict[str, dict] = {}
    groups: dict[str, str] = {}
    files = [path] if path.is_file() else sorted(
        path.rglob("*.json"), key=lambda f: (0 if "build-info" in f.parts else 1, -f.stat().st_mtime, f.as_posix()))
    for f in files:
        try:
            data = json.loads(f.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        found: list[tuple[dict, str]] = []
        if isinstance(data.get("ast"), dict):  # forge artifact; build-info files above win when present
            found.append((data["ast"], "artifacts"))
        output = data.get("output") if isinstance(data.get("output"), dict) else {}
        for container in (output.get("sources") or {}, data.get("sources") if isinstance(data.get("sources"), dict) else {}):
            for src in container.values():
                if isinstance(src, dict) and isinstance(src.get("ast"), dict):
                    found.append((src["ast"], f.as_posix()))
        for ast, group in found:
            name = ast.get("absolutePath")
            if not name and ast.get("name") == "SourceUnit":
                raise SolidityError(f"{f} holds the legacy solc AST (`--ast-json`, solc < 0.8)",
                                    hint="produce the compact AST: `solc --ast-compact-json` or Standard JSON")
            if name and name not in units:
                units[name] = ast
                groups[name] = group
    if not units:
        raise SolidityError(f"no solc AST found under {path}", hint="run `forge build --ast` first")
    return CompileResult(units=units, groups=groups, driver="prebuilt")
