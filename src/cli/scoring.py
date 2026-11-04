#!/usr/bin/env python3
"""Layer 10: risk score from 1 to 100 for a codebase, a single file or a live web page.

The score starts at 100 and every finding takes points off. It is strict on purpose:

* CRITICAL -25, HIGH -15, MEDIUM -8, LOW -3
* one rule can take at most three times its weight, so a hundred copies of the same mistake do not
  hide everything else, but three are enough to sink a project
* the score never goes below 1

Every deduction carries the file, the line, the severity, the layer it belongs to and a mitigation.

What gets read:

* Solidity (``.sol``): a source-level pass over every contract (input validation, access control on
  privileged writes, mutability, checks-effects-interactions, transient slots that are never cleared,
  spot prices, live-balance votes, unchecked calls ...). Rules tied to Presets 01-08 can be switched off.
  When a solc AST is available the preset matrix comes from the same detectors ``foundryguard gen`` uses.
* Backend and site code (``.py``, ``.js``/``.ts``, ``.html``, ``.php``): injection, unvalidated request
  input, secrets in source, TLS turned off, unsafe deserialization, mutable global state.
* A URL: one passive GET of the page. The response headers and the HTML/inline scripts it returns are
  checked. Nothing else is requested and nothing is fuzzed against a remote host.

``simulate()`` is the whole pipeline the desktop window runs: score, preset matrix, and, when ``forge``
is on PATH and the target is a Foundry project, a real ``foundryguard run --test`` whose broken
invariants become CRITICAL deductions. The result is written to ``foundryguard-report.html`` with the
score at the top, plus ``foundryguard-score.json``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html as _html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

if __package__:
    from . import reporter
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import reporter  # type: ignore

# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
SEVERITIES = tuple(WEIGHTS)
RULE_CAP = 3  # a rule takes at most RULE_CAP x its weight

LAYERS = {
    "L1": "input validation",
    "L2": "access control",
    "L3": "mutability",
    "L4": "state drift",
    "L5": "external calls",
    "L6": "injection",
    "L7": "secrets",
    "L8": "transport",
    "L9": "configuration",
    "L10": "fuzzed invariant",
}

PRESETS = {
    1: "ERC-4626 share math",
    2: "Vault / staking accounting",
    3: "Reward funding",
    4: "Hook read-reentrancy",
    5: "Transient-zero storage",
    6: "Flash-loan price squeeze",
    7: "Governance flash-mint",
    8: "View read-reentrancy",
}
ALL_PRESETS = frozenset(PRESETS)

VERDICTS = ((90, "HARDENED"), (75, "ACCEPTABLE"), (50, "EXPOSED"), (25, "CRITICAL"), (0, "BREACHED"))

SOL_EXT = {".sol"}
PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
HTML_EXT = {".html", ".htm"}
PHP_EXT = {".php"}
SCANNED_EXT = SOL_EXT | PY_EXT | JS_EXT | HTML_EXT | PHP_EXT
SKIP_DIRS = {".git", "node_modules", "lib", "out", "cache", "broadcast", "venv", ".venv", "env", "__pycache__",
             "dist", "build", "coverage", ".next", ".nuxt", "vendor", "site-packages", "test", "tests", "script",
             "scripts", "mocks", "fixtures", "foundryguard-reports"}
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_PAGE_BYTES = 2_000_000
USER_AGENT = "FoundryGuard/0.12 (passive single-page check)"
SCORE_JSON = "foundryguard-score.json"


@dataclass
class Finding:
    rule: str
    severity: str
    layer: str
    title: str
    file: str
    line: int
    evidence: str
    mitigation: str
    preset: int | None = None
    contract: str | None = None
    points: int = 0  # filled by score()

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else f"{self.file} (headers)"


@dataclass
class MatrixRow:
    contract: str
    file: str
    cells: dict  # preset id -> ARMED | FLAGGED | clear | off
    source: str  # "ast" or "text"


@dataclass
class ScoreResult:
    target: str
    kind: str  # solidity | web | mixed | url
    score: int
    findings: list[Finding]
    files_scanned: int = 0
    lines_scanned: int = 0
    presets: list[int] = field(default_factory=lambda: sorted(ALL_PRESETS))
    matrix: list[MatrixRow] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    forge: dict | None = None  # {"status", "passed", "failed", "report", "command", "returncode"}

    @property
    def verdict(self) -> str:
        return verdict(self.score)

    def counts(self) -> dict[str, int]:
        return {s: sum(f.severity == s for f in self.findings) for s in SEVERITIES}

    def as_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict
        d["counts"] = self.counts()
        d["matrix"] = [{**asdict(r), "cells": {str(k): v for k, v in r.cells.items()}} for r in self.matrix]
        return d


def verdict(score: int) -> str:
    for floor, word in VERDICTS:
        if score >= floor:
            return word
    return VERDICTS[-1][1]


def score(findings: list[Finding]) -> int:
    """Apply the deductions in order (worst first) and return the score, 1-100. Sets ``points`` on each."""
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.rule, f.file, f.line))
    spent: dict[str, int] = {}
    total = 0
    for f in findings:
        w = WEIGHTS[f.severity]
        cap = w * RULE_CAP
        take = max(0, min(w, cap - spent.get(f.rule, 0)))
        spent[f.rule] = spent.get(f.rule, 0) + take
        f.points = take
        total += take
    return max(1, min(100, 100 - total))


# --------------------------------------------------------------------------- #
# Source helpers
# --------------------------------------------------------------------------- #


def strip_comments(text: str, blank_strings: bool = True) -> str:
    """Comments (and string contents) replaced by spaces; offsets and newlines are kept."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if blank_strings:
                for k in range(i + 1, min(j, n)):
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def match_close(text: str, i: int, open_c: str = "{", close_c: str = "}") -> int:
    """Index of the bracket that closes the one at ``i`` (len(text) if unbalanced)."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_c:
            depth += 1
        elif text[j] == close_c:
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def snippet(raw_lines: list[str], line: int) -> str:
    if 1 <= line <= len(raw_lines):
        return raw_lines[line - 1].strip()[:160]
    return ""


# --------------------------------------------------------------------------- #
# Solidity
# --------------------------------------------------------------------------- #

CONTRACT_RE = re.compile(r"\b(abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)[^{;]*\{")
MEMBER_RE = re.compile(r"^\s*(?:(function)\s+([A-Za-z_]\w*)|(constructor)|(receive)|(fallback)|(modifier)\s+([A-Za-z_]\w*))\s*\(")
STATE_VAR_RE = re.compile(
    r"^(?P<type>(?:mapping\s*\(.*\)|[A-Za-z_][\w.]*(?:\s*\[[^\]]*\])*))\s+"
    r"(?P<attrs>(?:(?:public|private|internal|constant|immutable|transient|override(?:\s*\([^)]*\))?)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=[\s\S]*)?$")
NON_VAR_STARTS = ("using ", "event ", "error ", "function ", "modifier ", "type ", "constructor", "pragma ", "import ")
VISIBILITY = {"public", "external", "internal", "private"}
MUTABILITY = {"view", "pure", "payable"}
HEADER_KEYWORDS = VISIBILITY | MUTABILITY | {"virtual", "override", "returns", "nonpayable"}
REENTRANCY_GUARDS = re.compile(r"^(nonReentrant\w*|lock|noReentrancy|reentrancyGuard|noReentrant|whenNotLocked|guarded)$", re.I)
NON_AUTH_MODIFIERS = re.compile(r"^(nonReentrant\w*|lock|noReentrancy|whenNotPaused|whenPaused|initializer|reinitializer|"
                                r"onlyInitializing|updateReward|update\w*|accrue\w*|checkpoint\w*|valid\w*|nonZero\w*)$", re.I)
VALIDATION_MODIFIER = re.compile(r"(valid|check|nonzero|bounded|inrange|notzero)", re.I)
VALIDATION_CALL = re.compile(r"\b(require|revert|assert|_require\w*|_check\w*|_validate\w*|_verify\w*|_ensure\w*|"
                             r"_revertIf\w*|_assert\w*)\s*\(|\brevert\s+[A-Za-z_]")
AUTH_IN_BODY = re.compile(r"msg\.sender\s*(==|!=)|(==|!=)\s*msg\.sender|_checkOwner|_checkRole|hasRole\s*\(|_onlyOwner|"
                          r"isAuthorized|_authorize\w*|requiresAuth|_isOwner|_requireOwner|onlyOwner|_msgSender\(\)\s*(==|!=)")
PRIVILEGED_VAR = re.compile(r"^_?(owner|pendingOwner|admin|admins|governance|governor|guardian|oracle|priceFeed|feed|"
                            r"fee\w*|treasury|implementation|paused|minter|minters|operator|operators|signer|signers|"
                            r"keeper|rewardRate|rewardsDistribution|rate|price\w*|whitelist\w*|allowlist\w*|blacklist\w*|"
                            r"isAdmin|roles?|authorized\w*|controller|manager|router|strategy|vault)$", re.I)
EXTERNAL_CALL = re.compile(
    r"(?<![\w$])(?!abi\.|super\.|Math\.|SafeMath\.|SafeCast\.|Strings\.|Address\.functionStaticCall)"
    r"([A-Za-z_][\w$]*(?:\([^()]*\))?(?:\[[^\]]*\])?)\s*\.\s*"
    r"(call|delegatecall|transfer|send|safeTransfer|safeTransferFrom|transferFrom|sendValue|safeTransferETH|"
    r"functionCall\w*|deposit|withdraw|redeem|mint|swap\w*|flashLoan|execute\w*|on\w+Received)\s*(\{[^}]*\})?\s*\(")
LOW_LEVEL_CALL = re.compile(r"\.\s*(call|delegatecall)\s*(\{[^}]*\})?\s*\(")
SEND_CALL = re.compile(r"\.\s*send\s*\(")
BUILTIN_CALLS = {"require", "revert", "assert", "keccak256", "sha256", "ripemd160", "ecrecover", "addmod", "mulmod",
                 "address", "payable", "type", "bytes", "string", "bool", "abi", "gasleft", "blockhash", "emit",
                 "if", "for", "while", "return", "returns", "unchecked", "new"}
ELEMENTARY_CAST = re.compile(r"^(u?int\d*|bytes\d*|address|bool|string|payable)$")
SPOT_PRICE = re.compile(r"\b(getReserves|slot0|getAmountsOut|getAmountOut|get_dy|price0CumulativeLast)\s*\(")
LATEST_ROUND = re.compile(r"\blatestRoundData\s*\(")
LATEST_ANSWER = re.compile(r"\blatestAnswer\s*\(")
SELF_BALANCE = re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|address\s*\(\s*this\s*\)\s*\.\s*balance")
VOTE_FN = re.compile(r"^(castVote\w*|vote\w*|_castVote\w*|propose\w*)$")
PAST_VOTES = re.compile(r"getPastVotes|getPriorVotes|balanceOfAt|getVotesAt|snapshot|checkpoint", re.I)
DIV_BEFORE_MUL = re.compile(r"/\s*[\w.$]+(?:\([^()]*\))?(?:\[[^\]]*\])?\s*\)?\s*\*(?!\*)")
WEAK_RANDOM = re.compile(r"keccak256\s*\([^;]*\b(block\.timestamp|block\.prevrandao|block\.difficulty|blockhash|block\.number)\b")
TSTORE = re.compile(r"\btstore\s*\(\s*([^,()]+(?:\([^()]*\))?)\s*,\s*([^)]*?)\s*\)")


@dataclass
class SolFunction:
    name: str
    kind: str  # function | constructor | receive | fallback | modifier
    params: list[tuple[str, str]]  # (type, name)
    visibility: str
    mutability: str
    modifiers: list[str]
    header_start: int
    body_start: int  # offset of "{"
    body_end: int
    line: int

    @property
    def exposed(self) -> bool:
        return self.kind in ("function", "receive", "fallback") and self.visibility in ("public", "external")

    @property
    def state_changing(self) -> bool:
        return self.mutability not in ("view", "pure")


@dataclass
class SolContract:
    name: str
    kind: str
    line: int
    start: int
    end: int
    state_vars: dict[str, dict]  # name -> {"type", "mutable", "line"}
    functions: list[SolFunction]


def _split_params(text: str) -> list[tuple[str, str]]:
    out = []
    depth, cur = 0, ""
    for ch in text + ",":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts = cur.split()
            cur = ""
            if not parts:
                continue
            parts = [p for p in parts if p not in ("memory", "calldata", "storage", "payable", "indexed")]
            if len(parts) >= 2:
                out.append((parts[0], parts[-1]))
            elif parts:
                out.append((parts[0], ""))
            continue
        cur += ch
    return out


def _header_tokens(rest: str) -> tuple[str, str, list[str]]:
    rest = re.sub(r"\breturns\s*\(.*$", "", rest, flags=re.S)
    rest = re.sub(r"\boverride\s*\([^)]*\)", "override", rest)
    visibility, mutability, modifiers = "", "nonpayable", []
    for m in re.finditer(r"([A-Za-z_]\w*)\s*(\([^)]*\))?", rest):
        word = m.group(1)
        if word in VISIBILITY:
            visibility = word
        elif word in MUTABILITY:
            mutability = word
        elif word not in HEADER_KEYWORDS:
            modifiers.append(word)
    return visibility, mutability, modifiers


def parse_solidity(clean: str) -> list[SolContract]:
    contracts: list[SolContract] = []
    pos = 0
    while True:
        m = CONTRACT_RE.search(clean, pos)
        if not m:
            break
        open_i = m.end() - 1
        close_i = match_close(clean, open_i)
        kind = "abstract contract" if m.group(1).startswith("abstract") else m.group(1)
        c = SolContract(m.group(2), kind, line_of(clean, m.start()), open_i, close_i, {}, [])
        i = seg = open_i + 1
        while i < close_i:
            ch = clean[i]
            if ch == ";":
                stmt = " ".join(clean[seg:i].split())
                if stmt and not stmt.startswith(NON_VAR_STARTS):
                    vm = STATE_VAR_RE.match(stmt)
                    if vm and vm.group("name") not in VISIBILITY:
                        attrs = vm.group("attrs")
                        lead = len(clean[seg:i]) - len(clean[seg:i].lstrip())
                        c.state_vars[vm.group("name")] = {
                            "type": vm.group("type"),
                            "mutable": "constant" not in attrs and "immutable" not in attrs,
                            "transient": "transient" in attrs,
                            "line": line_of(clean, seg + lead),
                        }
                seg = i + 1
            elif ch == "{":
                end = match_close(clean, i)
                header = clean[seg:i]
                hm = MEMBER_RE.match(header)
                if hm:
                    kind_fn = ("function" if hm.group(1) else "constructor" if hm.group(3) else "receive" if hm.group(4)
                               else "fallback" if hm.group(5) else "modifier")
                    name = hm.group(2) or hm.group(7) or kind_fn
                    p_open = seg + hm.end() - 1
                    p_close = match_close(clean, p_open, "(", ")")
                    visibility, mutability, modifiers = _header_tokens(clean[p_close + 1:i])
                    if kind_fn in ("receive", "fallback") and not visibility:
                        visibility = "external"
                    if kind_fn == "constructor":
                        visibility = visibility or "public"
                    lead = len(header) - len(header.lstrip())
                    c.functions.append(SolFunction(
                        name, kind_fn, _split_params(clean[p_open + 1:p_close]), visibility, mutability, modifiers,
                        seg + lead, i, end, line_of(clean, seg + lead)))
                i = end
                seg = end + 1
            i += 1
        contracts.append(c)
        pos = close_i + 1 if close_i > m.end() else m.end()
    return contracts


def _write_re(var: str) -> re.Pattern[str]:
    idx = r"(?:\s*\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])*"
    member = r"(?:\s*\.\s*[A-Za-z_]\w*" + idx + r")*"
    v = re.escape(var)
    return re.compile(
        rf"(?<![\w.$]){v}{idx}{member}\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=|\+\+|--)"
        rf"|(?:\+\+|--)\s*{v}\b|\bdelete\s+{v}\b|(?<![\w.$]){v}{idx}{member}\s*\.\s*(?:push|pop)\s*\(")


class _SolFile:
    def __init__(self, rel: str, raw: str):
        self.rel = rel
        self.raw = raw
        self.lines = raw.splitlines()
        self.clean = strip_comments(raw)
        self.contracts = parse_solidity(self.clean)
        self._writes: dict[str, re.Pattern[str]] = {}

    def writes(self, c: SolContract, start: int, end: int) -> list[tuple[int, str]]:
        """(offset, var) for each write to a mutable state variable of ``c`` in [start, end)."""
        body = self.clean[start:end]
        out = []
        for var, meta in c.state_vars.items():
            if not meta["mutable"]:
                continue
            pat = self._writes.setdefault(var, _write_re(var))
            out += [(start + m.start(), var) for m in pat.finditer(body)]
        return sorted(out)

    def body(self, fn: SolFunction) -> str:
        return self.clean[fn.body_start:fn.body_end + 1]


def _validates(sf: _SolFile, c: SolContract, fn: SolFunction, seen: set[str] | None = None) -> bool:
    body = sf.body(fn)
    if VALIDATION_CALL.search(body) or any(VALIDATION_MODIFIER.search(m) for m in fn.modifiers):
        return True
    if re.search(r"\bif\s*\(", body) and re.search(r"\breturn\s*;", body):
        return True
    seen = seen or {fn.name}
    called = set(re.findall(r"(?<![\w.$])([A-Za-z_]\w*)\s*\(", body))
    for other in c.functions:
        if other.name in called and other.name not in seen and other.kind in ("function", "modifier"):
            seen.add(other.name)
            if _validates(sf, c, other, seen):
                return True
    return False


def _authorized(sf: _SolFile, c: SolContract, fn: SolFunction) -> bool:
    if any(not NON_AUTH_MODIFIERS.match(m) for m in fn.modifiers):
        return True
    body = sf.body(fn)
    if AUTH_IN_BODY.search(body):
        return True
    called = set(re.findall(r"(?<![\w.$])([A-Za-z_]\w*)\s*\(", body))
    for other in c.functions:
        if other.name in called and other.kind == "function" and other.visibility in ("internal", "private"):
            if AUTH_IN_BODY.search(sf.body(other)):
                return True
    return False


def _calls_out(sf: _SolFile, fn: SolFunction) -> bool:
    body = sf.body(fn)
    return bool(EXTERNAL_CALL.search(body) or LOW_LEVEL_CALL.search(body) or SEND_CALL.search(body)
                or re.search(r"\bassembly\b|\bemit\b|\bnew\s+[A-Z]|\bselfdestruct\b|\{\s*value\s*:", body))


def _local_calls(sf: _SolFile, fn: SolFunction) -> set[str]:
    names = set()
    for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)\s*\(", sf.body(fn)):
        n = m.group(1)
        if n in BUILTIN_CALLS or ELEMENTARY_CAST.match(n) or n[:1].isupper():
            continue
        prev = sf.body(fn)[:m.start()].rstrip()
        if prev.endswith("."):
            continue
        names.add(n)
    return names


def check_solidity(rel: str, raw: str, presets: frozenset[int]) -> tuple[list[Finding], list[SolContract]]:
    sf = _SolFile(rel, raw)
    out: list[Finding] = []

    def add(rule, sev, layer, title, offset_or_line, mitigation, preset=None, contract=None, is_line=False):
        if preset is not None and preset not in presets:
            return
        line = offset_or_line if is_line else line_of(sf.clean, offset_or_line)
        out.append(Finding(rule, sev, layer, title, rel, line, snippet(sf.lines, line), mitigation, preset, contract))

    pm = re.search(r"pragma\s+solidity\s+([^;]+);", sf.clean)
    pragma_line = line_of(sf.clean, pm.start()) if pm else 0
    if pm and re.search(r"[\^>~<*]|\|\|", pm.group(1)):
        add("SOL-FLOATING-PRAGMA", "LOW", "L9", f"Floating pragma `{pm.group(1).strip()}`", pragma_line,
            "Pin the compiler version you tested with (e.g. `pragma solidity 0.8.24;`).", is_line=True)

    for c in sf.contracts:
        if c.kind == "interface":
            continue
        cname = c.name
        fnames = {f.name for f in c.functions}
        for fn in c.functions:
            if fn.kind == "modifier":
                continue
            body = sf.body(fn)
            b0 = fn.body_start

            # L1 input validation
            checked_params = [p for p in fn.params if re.match(r"^(address|u?int\d*|bytes|string)$|\[\]$", p[0]) and p[1]]
            if fn.exposed and fn.state_changing and fn.kind == "function" and checked_params and not _validates(sf, c, fn):
                add("SOL-INPUT-VALIDATION", "HIGH", "L1",
                    f"`{fn.name}` takes {', '.join(p[1] for p in checked_params)} with no require/revert on any input",
                    fn.line, "Reject bad input up front: zero amounts, zero addresses, out-of-range values and empty "
                    "arrays should revert with a custom error before any state is touched.", contract=cname, is_line=True)
            # zero address stored into state
            for ptype, pname in fn.params:
                if ptype != "address" or not pname:
                    continue
                stored = re.search(rf"(?<![\w.$])([A-Za-z_]\w*)\s*=\s*{re.escape(pname)}\s*;", body)
                if stored and stored.group(1) in c.state_vars and not re.search(
                        rf"{re.escape(pname)}\s*(==|!=)\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*(==|!=)\s*{re.escape(pname)}", body):
                    add("SOL-ZERO-ADDRESS", "MEDIUM", "L1",
                        f"`{fn.name}` stores `{pname}` into `{stored.group(1)}` without a zero-address check",
                        b0 + stored.start(), f"Revert when `{pname} == address(0)`; a zero address here locks the "
                        "role or burns funds sent to it.", contract=cname)

            # L2 access control: privileged state written by anyone
            if fn.exposed and fn.kind == "function" and fn.state_changing and not fn.name.startswith(("initialize", "init")):
                if not _authorized(sf, c, fn):
                    for off, var in sf.writes(c, fn.body_start, fn.body_end):
                        if PRIVILEGED_VAR.match(var):
                            add("SOL-UNPROTECTED-MUTATION", "CRITICAL", "L2",
                                f"`{fn.name}` writes privileged `{var}` and anyone can call it", off,
                                "Gate the function with `onlyOwner`/`onlyRole` (or an explicit `msg.sender` check) "
                                "and emit an event for the change.", contract=cname)
                            break

            # unguarded initializer
            if fn.exposed and fn.kind == "function" and re.match(r"^(initialize\w*|init)$", fn.name):
                guarded = any(m in ("initializer", "reinitializer", "onlyInitializing") for m in fn.modifiers) or \
                    re.search(r"\b(_?initialized|_initializing|initialized)\b", body)
                if not guarded:
                    add("SOL-UNGUARDED-INITIALIZER", "CRITICAL", "L2",
                        f"`{fn.name}` can be called again (no `initializer` guard)", fn.line,
                        "Use OpenZeppelin `initializer` (or a one-shot `initialized` flag) and call "
                        "`_disableInitializers()` in the constructor of the implementation.", contract=cname, is_line=True)

            # L3 mutability
            if fn.exposed and fn.kind == "function" and fn.mutability == "nonpayable":
                writes = sf.writes(c, fn.body_start, fn.body_end)
                locals_ = _local_calls(sf, fn) & fnames
                if not writes and not _calls_out(sf, fn) and not locals_ and not re.search(r"\b_\w+\s*\(", body):
                    add("SOL-MUTABILITY", "LOW", "L3",
                        f"`{fn.name}` changes no state but is not declared view/pure", fn.line,
                        "Declare it `view` (or `pure`) so callers and the compiler can rely on it not mutating state.",
                        contract=cname, is_line=True)
            if fn.mutability == "payable" and fn.kind == "function" and "msg.value" not in body \
                    and not re.search(r"\b_\w+\s*\(", body) and not re.search(r"\bassembly\b", body):
                add("SOL-PAYABLE-UNUSED", "MEDIUM", "L3",
                    f"`{fn.name}` is payable but never reads msg.value, so sent ether is stuck", fn.line,
                    "Drop `payable`, or account for `msg.value` (and refund or reject unexpected ether).",
                    contract=cname, is_line=True)

            # L4 state drift: interaction before effect
            if fn.exposed and fn.state_changing and not any(REENTRANCY_GUARDS.match(m) for m in fn.modifiers):
                calls = [m for m in EXTERNAL_CALL.finditer(body)] + [m for m in LOW_LEVEL_CALL.finditer(body)]
                if calls:
                    first = min(m.start() for m in calls)
                    late = [(off, v) for off, v in sf.writes(c, fn.body_start, fn.body_end) if off > b0 + first]
                    if late:
                        native = re.search(r"\{\s*value\s*:|\.\s*(transfer|send)\s*\(\s*[^,()]*\)|sendValue|safeTransferETH", body)
                        add("SOL-CEI-DRIFT", "HIGH", "L4",
                            f"`{fn.name}` writes `{late[0][1]}` after an external call (hidden state drift during the call)",
                            late[0][0], "Follow checks-effects-interactions: update every balance and total before the "
                            "call, or add `nonReentrant` to this and every view-coupled entry point.",
                            preset=8 if native else 4, contract=cname)

            # L5 external calls
            for m in LOW_LEVEL_CALL.finditer(body):
                stmt_start = max(body.rfind(";", 0, m.start()), body.rfind("{", 0, m.start()), body.rfind("}", 0, m.start()))
                stmt = body[stmt_start + 1:m.start()]
                if not re.search(r"=|\breturn\b|require\s*\(|\bif\s*\(", stmt):
                    add("SOL-UNCHECKED-CALL", "HIGH", "L5", "Return value of a low-level call is ignored", b0 + m.start(),
                        "Capture `(bool ok, ) = ...` and revert when `!ok`, or use `Address.sendValue`/`functionCall`.",
                        contract=cname)
                if m.group(1) == "delegatecall":
                    callee = body[:m.start()].rstrip()
                    target = re.search(r"([\w$.]+(?:\s*\([^()]*\))?)\s*$", callee)
                    tname = " ".join(target.group(1).split()) if target else "?"
                    if re.fullmatch(r"address\s*\(\s*this\s*\)", tname):
                        continue  # multicall into itself
                    user = any(p[1] == tname for p in fn.params)
                    add("SOL-DELEGATECALL", "CRITICAL" if user else "MEDIUM", "L5",
                        f"delegatecall into {'caller-supplied' if user else 'a variable'} target `{tname}`", b0 + m.start(),
                        "Only delegatecall into an immutable, audited implementation; never into an address the caller passes.",
                        contract=cname)
            for m in SEND_CALL.finditer(body):
                stmt_start = max(body.rfind(";", 0, m.start()), body.rfind("{", 0, m.start()))
                if not re.search(r"=|require\s*\(|\bif\s*\(", body[stmt_start + 1:m.start()]):
                    add("SOL-UNCHECKED-CALL", "HIGH", "L5", "Return value of `send` is ignored", b0 + m.start(),
                        "Check the bool `send` returns, or use `call{value:}` with a checked result.", contract=cname)

            # Presets
            if fn.exposed and SPOT_PRICE.search(body):
                m = SPOT_PRICE.search(body)
                add("SOL-SPOT-PRICE", "HIGH", "L4", f"`{fn.name}` prices off a pool spot read (`{m.group(1)}`)",
                    b0 + m.start(), "Use a TWAP or a Chainlink feed with bounds; a spot reserve read moves inside a "
                    "flash loan.", preset=6, contract=cname)
            m = LATEST_ROUND.search(body)
            if m and not re.search(r"updatedAt|answeredInRound|block\.timestamp\s*-", body):
                add("SOL-STALE-ORACLE", "MEDIUM", "L4", "Oracle answer used without a staleness check", b0 + m.start(),
                    "Check `updatedAt` against a heartbeat and `answer > 0` before using the price.", preset=6, contract=cname)
            m = LATEST_ANSWER.search(body)
            if m:
                add("SOL-STALE-ORACLE", "MEDIUM", "L4", "`latestAnswer()` is deprecated and carries no timestamp",
                    b0 + m.start(), "Use `latestRoundData()` and check `updatedAt` and `answer > 0`.", preset=6, contract=cname)
            m = SELF_BALANCE.search(body)
            if m and fn.kind == "function":
                add("SOL-DONATION-DRIFT", "MEDIUM", "L4",
                    f"`{fn.name}` reads the contract's own balance, which anyone can move with a direct transfer",
                    b0 + m.start(), "Track deposits in an internal accounting variable instead of `balanceOf(this)` / "
                    "`address(this).balance`.", preset=6 if "price" in fn.name.lower() or "convert" in fn.name.lower() else 1,
                    contract=cname)
            if VOTE_FN.match(fn.name) and fn.exposed and re.search(r"balanceOf\s*\(", body) and not PAST_VOTES.search(body):
                m = re.search(r"balanceOf\s*\(", body)
                add("SOL-FLASH-VOTE", "HIGH", "L4", f"`{fn.name}` weighs votes by live balance",
                    b0 + m.start(), "Weigh votes by a past checkpoint (`getPastVotes(account, proposalSnapshot)`), "
                    "never the current balance.", preset=7, contract=cname)
            if re.search(r"totalSupply\s*(\(\s*\))?\s*==\s*0\s*\?", body) and re.search(r"convertTo|preview|deposit|mint|shares", fn.name, re.I) \
                    and not re.search(r"_decimalsOffset|virtual|\+\s*1\b|10\s*\*\*", raw):
                m = re.search(r"totalSupply\s*(\(\s*\))?\s*==\s*0", body)
                add("SOL-SHARE-INFLATION", "HIGH", "L4", "First-depositor share math with no virtual offset",
                    b0 + m.start(), "Add virtual shares/assets (`_decimalsOffset`) or seed the vault with dead shares.",
                    preset=1, contract=cname)
            for m in re.finditer(r"/\s*\(?\s*(total\w*|_total\w*)\s*(\(\s*\))?", body, re.I):
                var = m.group(1)
                if not re.search(rf"{re.escape(var)}\s*(\(\s*\))?\s*(==|!=|>|<=)\s*0|0\s*(==|!=|<)\s*{re.escape(var)}", body):
                    add("SOL-DIV-BY-TOTAL", "MEDIUM", "L4", f"Division by `{var}`, which can be zero",
                        b0 + m.start(), f"Branch on `{var} == 0` before dividing (return the stored value instead).",
                        preset=2, contract=cname)
                    break
            if re.match(r"^(notifyRewardAmount|setRewardRate|fund\w*|addReward\w*)$", fn.name) and fn.exposed \
                    and not SELF_BALANCE.search(body) and not re.search(r"transferFrom|safeTransferFrom", body):
                add("SOL-UNFUNDED-REWARDS", "HIGH", "L4",
                    f"`{fn.name}` sets a reward schedule without checking the tokens are there", fn.line,
                    "Require `rewardRate * duration <= rewardToken.balanceOf(address(this))` (or pull the tokens in "
                    "the same call).", preset=3, contract=cname, is_line=True)

            # weak randomness, division before multiplication
            m = WEAK_RANDOM.search(body)
            if m:
                add("SOL-WEAK-RANDOMNESS", "MEDIUM", "L4", f"Randomness from `{m.group(1)}`", b0 + m.start(),
                    "Use Chainlink VRF or commit-reveal; block values are known to (and set by) the block builder.",
                    contract=cname)
            m = DIV_BEFORE_MUL.search(body)
            if m:
                add("SOL-DIV-BEFORE-MUL", "MEDIUM", "L4", "Division before multiplication truncates", b0 + m.start(),
                    "Multiply first, or use `Math.mulDiv(a, b, c)` for full precision.", contract=cname)
            for m in re.finditer(r"\bunchecked\s*\{", body):
                inner = body[m.end():match_close(body, m.end() - 1)]
                if re.search(r"[\w)\]]\s*[-*]\s*[\w(]", inner):
                    add("SOL-UNCHECKED-MATH", "LOW", "L4", "Subtraction/multiplication inside `unchecked`",
                        b0 + m.start(), "Keep `unchecked` to loop counters and proven bounds; document the bound "
                        "next to each unchecked operation.", contract=cname)

        # Preset 05: tstore slots never written back to zero
        stores: dict[str, list[tuple[int, str]]] = {}
        for m in TSTORE.finditer(sf.clean, c.start, c.end):
            stores.setdefault(" ".join(m.group(1).split()), []).append((m.start(), m.group(2).strip()))
        for slot, writes in stores.items():
            if not any(v in ("0", "0x0", "0x00", "false") for _, v in writes):
                add("SOL-TRANSIENT-LEAK", "HIGH", "L4", f"Transient slot `{slot}` is set but never cleared",
                    writes[0][0], "Write the slot back to 0 before the call returns; EIP-1153 clears it only when the "
                    "whole transaction ends, so the next call in a multicall or callback sees the stale value.",
                    preset=5, contract=cname)
        for var, meta in c.state_vars.items():
            if meta.get("transient") and not re.search(rf"\b(delete\s+{re.escape(var)}\b|{re.escape(var)}\s*=\s*(0|false|address\(0\))\s*;)",
                                                      sf.clean[c.start:c.end]):
                add("SOL-TRANSIENT-LEAK", "HIGH", "L4", f"Transient variable `{var}` is never reset", meta["line"],
                    "Reset it (`delete x;`) at the end of every function that sets it.", preset=5, contract=cname, is_line=True)

    for m in re.finditer(r"\btx\.origin\b", sf.clean):
        add("SOL-TX-ORIGIN", "CRITICAL", "L2", "Authorization through `tx.origin`", m.start(),
            "Use `msg.sender`; any contract the user calls can act as them under `tx.origin`.")
    for m in re.finditer(r"\bselfdestruct\s*\(", sf.clean):
        add("SOL-SELFDESTRUCT", "HIGH", "L3", "`selfdestruct` in deployed code", m.start(),
            "Remove it; after Cancun it only moves ether, and before that it could brick every user of the contract.")
    return out, sf.contracts


# --------------------------------------------------------------------------- #
# Backend / site code
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LineRule:
    rule: str
    severity: str
    layer: str
    title: str
    pattern: re.Pattern[str]
    mitigation: str
    langs: frozenset[str]
    needs: re.Pattern[str] | None = None  # the file must also match this
    unless: re.Pattern[str] | None = None  # skip when the file matches this


PY, JS, HTML, PHP = "py", "js", "html", "php"
WEB = frozenset({PY, JS, HTML, PHP})
VALIDATION_LIBS = re.compile(r"pydantic|marshmallow|wtforms|cerberus|voluptuous|jsonschema|attrs\.validators|"
                             r"\bjoi\b|\bzod\b|\byup\b|express-validator|\bajv\b|class-validator|celebrate|"
                             r"filter_var|filter_input|Validator::|validate\(|\.parse\(|schema\.", re.I)
SECRET_TERMS = re.compile(r"token|password|passwd|secret|nonce|otp|salt|session|reset", re.I)


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


LINE_RULES: tuple[LineRule, ...] = (
    LineRule("WEB-EVAL", "CRITICAL", "L6", "Dynamic code execution", _r(r"(?<![\w.])(eval|exec)\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"`]"),
             "Never evaluate strings; parse the data (json.loads / JSON.parse) and dispatch on known values.", WEB),
    LineRule("WEB-COMMAND", "CRITICAL", "L6", "Shell command built at runtime",
             _r(r"os\.system\s*\(|os\.popen\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|child_process|\bexecSync\s*\(|"
                r"\bshell_exec\s*\(|\bpassthru\s*\(|\bproc_open\s*\(|(?<![\w.>])system\s*\("),
             "Run commands with an argument list and no shell (`subprocess.run([...], shell=False)`, `execFile`).", WEB),
    LineRule("WEB-SQL", "CRITICAL", "L6", "SQL built from strings",
             _r(r"(execute|executemany|query|raw|prepare)\s*\(\s*(f['\"]|['\"][^'\"]*\b(select|insert|update|delete)\b[^'\"]*['\"]\s*(\+|%|\.format)|`[^`]*\$\{)", re.I),
             "Use parameterized queries (`cursor.execute(sql, params)`, `db.query(sql, [params])`) or the ORM.", WEB),
    LineRule("WEB-XSS", "HIGH", "L6", "Untrusted HTML written into the page",
             _r(r"\.(innerHTML|outerHTML)\s*\+?=|document\.write\s*\(|dangerouslySetInnerHTML|\bv-html\b|\|\s*safe\b|"
                r"\bMarkup\s*\(|insertAdjacentHTML|echo\s+\$_(GET|POST|REQUEST)"),
             "Write text with `textContent` / framework escaping; sanitize with DOMPurify when HTML is required.", WEB),
    LineRule("WEB-INPUT-VALIDATION", "HIGH", "L1", "Request input used with no validation layer in the file",
             _r(r"request\.(args|form|values|json|data|files|GET|POST|get_json)\b|\breq\.(body|query|params|cookies)\b|"
                r"\$_(GET|POST|REQUEST|COOKIE)\b|new\s+URLSearchParams\s*\(|location\.(hash|search)\b"),
             "Validate every field against a schema (pydantic, zod, joi, express-validator) before use: type, "
             "length, range, allowed values.", WEB, unless=VALIDATION_LIBS),
    LineRule("WEB-SECRET", "CRITICAL", "L7", "Credential in source",
             _r(r"(api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token|private[_-]?key)\s*['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]|"
                r"AKIA[0-9A-Z]{16}|\bsk-[A-Za-z0-9_-]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|['\"]0x[0-9a-fA-F]{64}['\"]", re.I),
             "Move the secret to the environment or a secret manager, rotate it now, and purge it from git history.", WEB),
    LineRule("WEB-TLS-OFF", "HIGH", "L8", "TLS certificate checks disabled",
             _r(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)", re.I),
             "Keep verification on; pin or trust the right CA bundle instead.", WEB),
    LineRule("WEB-PLAIN-HTTP", "MEDIUM", "L8", "Plain http:// endpoint",
             _r(r"['\"(]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.)"),
             "Use https:// for every endpoint and asset.", WEB),
    LineRule("WEB-DESERIALIZE", "HIGH", "L6", "Unsafe deserialization",
             _r(r"pickle\.loads?\s*\(|marshal\.loads\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)|\bunserialize\s*\(|jsonpickle\.decode"),
             "Deserialize only data formats without code execution (JSON, `yaml.safe_load`).", WEB),
    LineRule("WEB-DEBUG", "MEDIUM", "L9", "Debug mode enabled",
             _r(r"\bdebug\s*=\s*True|\bDEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|display_errors\s*,\s*['\"]?(1|on)", re.I),
             "Read debug flags from the environment and default them to off.", WEB),
    LineRule("WEB-CORS-ANY", "MEDIUM", "L9", "CORS allows any origin",
             _r(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|CORS\s*\(\s*app\s*\)|allow_origins\s*=\s*\[\s*['\"]\*"),
             "List the exact origins that may call the API.", WEB),
    LineRule("WEB-TOKEN-STORAGE", "MEDIUM", "L7", "Auth token in localStorage",
             _r(r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(token|jwt|auth|session)", re.I),
             "Keep session tokens in `HttpOnly; Secure; SameSite` cookies, out of reach of page scripts.", frozenset({JS, HTML})),
    LineRule("WEB-WEAK-RANDOM", "LOW", "L7", "Non-cryptographic random in security code",
             _r(r"Math\.random\s*\(|random\.(random|randint|choice)\s*\(|\bmt_rand\s*\(|\brand\s*\("),
             "Use `crypto.getRandomValues` / `secrets` / `random_bytes` for tokens and nonces.", WEB, needs=SECRET_TERMS),
    LineRule("WEB-WEAK-HASH", "LOW", "L7", "MD5/SHA-1 in use", _r(r"\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\b|createHash\(\s*['\"](md5|sha1)", re.I),
             "Use bcrypt/argon2 for passwords and SHA-256 or better elsewhere.", WEB),
    LineRule("WEB-JWT-NONE", "HIGH", "L2", "JWT signature not verified",
             _r(r"algorithms\s*=\s*\[?\s*['\"]none|verify_signature['\"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true", re.I),
             "Verify the signature with a fixed algorithm list and check `exp`.", WEB),
    LineRule("WEB-OPEN-REDIRECT", "MEDIUM", "L1", "Redirect target taken from the request",
             _r(r"redirect\s*\(\s*(request|req)\.|res\.redirect\s*\(\s*req\.|header\s*\(\s*['\"]Location:\s*['\"]\s*\.\s*\$_"),
             "Redirect only to relative paths or an allowlist of hosts.", WEB),
    LineRule("WEB-PATH-TRAVERSAL", "HIGH", "L1", "File path taken from the request",
             _r(r"(open|send_file|send_from_directory|readFile\w*|sendFile|createReadStream|file_get_contents|include|require)\s*\([^)]*(request\.|req\.|\$_(GET|POST|REQUEST))"),
             "Resolve the path, check it stays inside the allowed directory, and reject `..`.", WEB),
    LineRule("WEB-GLOBAL-STATE", "MEDIUM", "L4", "Handler mutates module-level state",
             _r(r"^\s+global\s+[A-Za-z_]\w*"),
             "Keep request state local or in a store with explicit locking; globals drift between requests and workers.",
             frozenset({PY})),
    LineRule("WEB-MUTABLE-DEFAULT", "MEDIUM", "L4", "Mutable default argument shared between calls",
             _r(r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))"),
             "Default to `None` and create the list/dict inside the function.", frozenset({PY})),
)


def _lang(path: str) -> str | None:
    ext = Path(path).suffix.lower()
    return (PY if ext in PY_EXT else JS if ext in JS_EXT else HTML if ext in HTML_EXT else PHP if ext in PHP_EXT else None)


def check_text(rel: str, raw: str, lang: str) -> list[Finding]:
    lines = raw.splitlines()
    # Strip comments for C-like and Python sources so commented-out code does not count.
    if lang == PY:
        clean_lines = [re.sub(r"(^|\s)#.*$", r"\1", ln) for ln in lines]
    elif lang in (JS, PHP):
        clean_lines = strip_comments(raw, blank_strings=False).splitlines()
    else:
        clean_lines = lines
    out: list[Finding] = []
    for rule in LINE_RULES:
        if lang not in rule.langs:
            continue
        if rule.needs and not rule.needs.search(raw):
            continue
        if rule.unless and rule.unless.search(raw):
            continue
        for i, ln in enumerate(clean_lines, 1):
            if len(ln) > 4000:
                continue
            if rule.pattern.search(ln):
                out.append(Finding(rule.rule, rule.severity, rule.layer, rule.title, rel, i, snippet(lines, i),
                                   rule.mitigation))
    if lang == HTML:
        out += check_html(rel, raw)
    return out


FORM_RE = re.compile(r"<form\b[^>]*>", re.I)


def check_html(rel: str, raw: str, page_url: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    lines = raw.splitlines()
    for m in FORM_RE.finditer(raw):
        tag = m.group(0)
        if not re.search(r"method\s*=\s*['\"]?post", tag, re.I):
            continue
        end = raw.lower().find("</form>", m.end())
        inner = raw[m.end(): end if end >= 0 else len(raw)]
        if not re.search(r"csrf|xsrf|authenticity_token|_token|nonce", inner, re.I):
            ln = line_of(raw, m.start())
            out.append(Finding("WEB-CSRF", "MEDIUM", "L2", "POST form without an anti-CSRF token", rel, ln,
                               snippet(lines, ln), "Add a per-session CSRF token to the form and check it server side; "
                               "set cookies `SameSite=Lax` or stricter."))
    host = urllib.parse.urlparse(page_url).netloc if page_url else None
    for m in re.finditer(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", raw, re.I):
        src, tag = m.group(1), m.group(0)
        parsed = urllib.parse.urlparse(src)
        third_party = parsed.netloc and parsed.netloc != host
        if third_party and "integrity=" not in tag.lower():
            ln = line_of(raw, m.start())
            out.append(Finding("WEB-NO-SRI", "LOW", "L8", f"Third-party script without integrity hash ({parsed.netloc})",
                               rel, ln, snippet(lines, ln),
                               "Add `integrity=\"sha384-...\"` and `crossorigin`, or self-host the script."))
    if page_url and page_url.startswith("https://"):
        for m in re.finditer(r"<(script|img|link|iframe|form)\b[^>]*\b(src|href|action)\s*=\s*['\"]http://", raw, re.I):
            ln = line_of(raw, m.start())
            out.append(Finding("WEB-MIXED-CONTENT", "MEDIUM", "L8", "http:// resource on an https page", rel, ln,
                               snippet(lines, ln), "Load every resource over https."))
    return out


# --------------------------------------------------------------------------- #
# URL (passive)
# --------------------------------------------------------------------------- #


def is_url(text: str) -> bool:
    return bool(re.match(r"^https?://[^\s/$.?#].[^\s]*$", text.strip(), re.I))


def fetch(url: str, timeout: float = 15.0, opener=None) -> tuple[str, int, list[tuple[str, str]], str]:
    """One GET. Returns (final url, status, headers, body). ``opener`` is injectable for tests."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    open_fn = opener or urllib.request.urlopen
    try:
        resp = open_fn(req, timeout=timeout)
    except urllib.error.HTTPError as exc:  # a 4xx/5xx page still has headers and a body
        resp = exc
    with resp:
        body = resp.read(MAX_PAGE_BYTES)
        headers = list(resp.headers.items()) if resp.headers else []
        charset = resp.headers.get_content_charset() if resp.headers else None
        return resp.geturl(), getattr(resp, "status", None) or resp.getcode(), headers, body.decode(charset or "utf-8", "replace")


def check_headers(url: str, headers: list[tuple[str, str]]) -> list[Finding]:
    h: dict[str, list[str]] = {}
    for k, v in headers:
        h.setdefault(k.lower(), []).append(v)
    one = {k: v[0] for k, v in h.items()}
    out: list[Finding] = []

    def add(rule, sev, layer, title, mitigation, evidence=""):
        out.append(Finding(rule, sev, layer, title, url, 0, evidence, mitigation))

    https = url.lower().startswith("https://")
    if not https:
        add("URL-NO-TLS", "HIGH", "L8", "Page served over plain http", "Serve the site over https only and redirect http to it.")
    csp = one.get("content-security-policy", "")
    if not csp:
        add("URL-NO-CSP", "HIGH", "L9", "No Content-Security-Policy header",
            "Send a CSP that limits script sources (`default-src 'self'`; no `unsafe-inline`).")
    elif re.search(r"unsafe-inline|unsafe-eval", csp):
        add("URL-WEAK-CSP", "MEDIUM", "L9", "CSP allows unsafe-inline / unsafe-eval",
            "Drop `unsafe-inline` and `unsafe-eval`; use nonces or hashes for inline scripts.", csp[:160])
    if https and "strict-transport-security" not in one:
        add("URL-NO-HSTS", "MEDIUM", "L8", "No Strict-Transport-Security header",
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.")
    if one.get("x-content-type-options", "").lower() != "nosniff":
        add("URL-NO-NOSNIFF", "LOW", "L9", "No `X-Content-Type-Options: nosniff`", "Send `X-Content-Type-Options: nosniff`.")
    if "x-frame-options" not in one and "frame-ancestors" not in csp:
        add("URL-CLICKJACKING", "MEDIUM", "L9", "Page can be framed by any site",
            "Send `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`).")
    if one.get("access-control-allow-origin", "").strip() == "*":
        add("URL-CORS-ANY", "MEDIUM", "L9", "`Access-Control-Allow-Origin: *`", "Allow only the origins that need the API.")
    for cookie in h.get("set-cookie", []):
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        missing = [a for a, ok in (("Secure", "secure" in low or not https), ("HttpOnly", "httponly" in low),
                                   ("SameSite", "samesite" in low)) if not ok]
        if missing:
            add("URL-COOKIE-FLAGS", "MEDIUM", "L7", f"Cookie `{name}` lacks {', '.join(missing)}",
                "Set `Secure; HttpOnly; SameSite=Lax` (or Strict) on session cookies.", cookie[:160])
    for key in ("server", "x-powered-by"):
        if key in one and re.search(r"\d", one[key]):
            add("URL-VERSION-LEAK", "LOW", "L9", f"`{key}` header discloses a version ({one[key][:60]})",
                f"Remove the version from the `{key}` header.")
    return out


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def discover(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(filenames):
            p = Path(dirpath) / f
            if p.suffix.lower() not in SCANNED_EXT or f.endswith((".t.sol", ".s.sol", ".min.js", ".d.ts")):
                continue
            if re.search(r"(^test_|_test\.py$|\.test\.|\.spec\.)", f):
                continue
            files.append(p)
            if len(files) >= MAX_FILES:
                return files
    return files


def score_path(target: Path, presets: Iterable[int] = ALL_PRESETS) -> tuple[ScoreResult, dict[str, list[SolContract]]]:
    presets = frozenset(presets)
    target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"{target} does not exist")
    base = target.parent if target.is_file() else target
    files = discover(target)
    findings: list[Finding] = []
    sol_contracts: dict[str, list[SolContract]] = {}
    lines = 0
    kinds = set()
    notes = []
    for p in files:
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                notes.append(f"skipped {p.name}: larger than {MAX_FILE_BYTES // 1000} KB")
                continue
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            notes.append(f"skipped {p.name}: {exc}")
            continue
        rel = p.relative_to(base).as_posix() if p != base else p.name
        lines += raw.count("\n") + 1
        if p.suffix.lower() in SOL_EXT:
            kinds.add("solidity")
            f, contracts = check_solidity(rel, raw, presets)
            findings += f
            sol_contracts[rel] = contracts
        else:
            lang = _lang(p.name)
            if lang:
                kinds.add("web")
                findings += check_text(rel, raw, lang)
    if not files:
        notes.append("no .sol/.py/.js/.ts/.html/.php files found (test, lib and node_modules dirs are skipped)")
    kind = "mixed" if len(kinds) > 1 else (kinds.pop() if kinds else "empty")
    result = ScoreResult(str(target), kind, score(findings), findings, len(files), lines, sorted(presets), notes=notes)
    if not files:
        result.score = 1
    return result, sol_contracts


def score_url(url: str, presets: Iterable[int] = ALL_PRESETS, opener=None, timeout: float = 15.0) -> ScoreResult:
    final, status, headers, body = fetch(url, timeout, opener)
    findings = check_headers(final, headers)
    lines = body.splitlines()
    for f in check_text(final, body, HTML):
        findings.append(f)
    for f in check_html(final, body, final):
        if f.rule in ("WEB-MIXED-CONTENT", "WEB-NO-SRI") and any(
                g.rule == f.rule and g.line == f.line for g in findings):
            continue
        findings.append(f)
    notes = [f"one GET of {final} (HTTP {status}); headers and the returned HTML were checked, nothing else was "
             "requested and nothing was fuzzed against the host"]
    if final != url:
        notes.append(f"redirected from {url}")
    return ScoreResult(final, "url", score(findings), findings, 1, len(lines), sorted(frozenset(presets)), notes=notes)


# --------------------------------------------------------------------------- #
# Preset matrix
# --------------------------------------------------------------------------- #


def matrix_from_targets(targets, unmatched, presets: frozenset[int]) -> list[MatrixRow]:
    rows = []
    for t in list(targets) + list(unmatched):
        cats = {f.get("category") for f in t.flows}
        armed = {
            1: t.is_erc4626,
            2: bool(cats & {"deposit", "withdraw", "stake_lock", "stake_in", "stake_out"}) and not t.is_erc4626,
            3: "reward" in cats,
            4: bool(t.hooks) and not t.read_reentrancy,
            5: bool(t.transient),
            6: bool(t.pricing),
            7: bool(t.governance),
            8: bool(t.read_reentrancy),
        }
        rows.append(MatrixRow(t.name, t.contract.get("file", ""),
                              {p: ("off" if p not in presets else "ARMED" if armed[p] else "clear") for p in PRESETS}, "ast"))
    return rows


def matrix_from_text(sol: dict[str, list[SolContract]], findings: list[Finding], presets: frozenset[int]) -> list[MatrixRow]:
    rows = []
    for rel, contracts in sol.items():
        for c in contracts:
            if c.kind in ("interface", "library"):
                continue
            hit = {f.preset for f in findings if f.file == rel and f.contract == c.name and f.preset}
            rows.append(MatrixRow(c.name, rel, {p: ("off" if p not in presets else "FLAGGED" if p in hit else "clear")
                                                for p in PRESETS}, "text"))
    return rows


def merge_text_flags(rows: list[MatrixRow], findings: list[Finding]) -> None:
    for r in rows:
        for f in findings:
            if f.preset and f.contract == r.contract and r.cells.get(f.preset) == "clear":
                r.cells[f.preset] = "FLAGGED"


# --------------------------------------------------------------------------- #
# Simulation pipeline (used by the desktop window and `foundryguard score`)
# --------------------------------------------------------------------------- #

Progress = Callable[[str], None]


class Cancelled(Exception):
    pass


def default_report_dir(target: str) -> Path:
    if is_url(target):
        host = re.sub(r"[^\w.-]", "_", urllib.parse.urlparse(target).netloc) or "site"
        return Path.home() / "foundryguard-reports" / host
    p = Path(target).expanduser().resolve()
    return p if p.is_dir() else p.parent


def _foundry_root(p: Path) -> Path | None:
    p = p if p.is_dir() else p.parent
    for d in (p, *p.parents):
        if (d / "foundry.toml").is_file():
            return d
    return None


def _blueprint_matrix(target: Path, presets: frozenset[int], ast_path: str | None, progress: Progress) -> tuple[list[MatrixRow] | None, str | None]:
    if __package__:
        from . import injector, parser
    else:
        import injector  # type: ignore
        import parser  # type: ignore
    root = target if target.is_dir() else target.parent
    paths: list[str] = [] if target.is_dir() else [target.name]
    if target.is_dir() and not ast_path and not any((root / d).is_dir() for d in parser.DEFAULT_SOURCE_DIRS):
        paths = ["."]
    try:
        progress("AST: compiling with the local Solidity compiler")
        config = parser.load_config(root)
        bp = parser.build_blueprint(root, paths, config=config, ast_path=ast_path)
        unmatched: list = []
        targets = injector.build_targets(bp, None, config, unmatched)
        return matrix_from_targets(targets, unmatched, presets), None
    except (Exception, SystemExit) as exc:  # no compiler, a compile error: fall back to the text detectors
        msg = getattr(exc, "headline", None) or str(exc) or exc.__class__.__name__
        return None, f"AST unavailable ({msg.splitlines()[0][:200]}); the preset matrix comes from the source-level detectors"


def _run_forge(root: Path, progress: Progress, cancel, timeout: float) -> tuple[dict, list[Finding], object]:
    cli = Path(__file__).with_name("foundryguard.py")
    report_md = root / reporter.REPORT_FILE
    cmd = [sys.executable, str(cli), "run", "--root", str(root), "--test", "--no-html", "--report", str(report_md)]
    progress("forge: " + " ".join(cmd[2:]))
    proc = subprocess.Popen(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    captured: list[str] = []
    start = time.monotonic()
    assert proc.stdout is not None
    for line in proc.stdout:
        captured.append(line)
        if line.strip():
            progress("  " + line.rstrip()[:200])
        if (cancel and cancel()) or time.monotonic() - start > timeout:
            proc.kill()
            proc.wait()
            raise Cancelled("cancelled" if cancel and cancel() else f"forge run exceeded {int(timeout)}s")
    rc = proc.wait()
    text = "".join(captured)
    run = reporter.parse_text(text, "foundryguard run --test")
    try:
        reporter.resolve_from_source(run, root)
        reporter.load_persisted_sequences(run, root)
    except Exception:  # best effort: the score page still lists the failures without sequences
        pass
    findings = []
    for t in run.failures:
        file = t.file or t.suite.split(":")[0]
        line = 0
        p = root / file
        if p.is_file():
            m = re.search(rf"function\s+{re.escape(t.func)}\s*\(", p.read_text(errors="replace"))
            line = line_of(p.read_text(errors="replace"), m.start()) if m else 0
        findings.append(Finding("FUZZ-INVARIANT-BROKEN", "CRITICAL", "L10",
                                f"Invariant `{t.func}` broken by a fuzzed call sequence", file, line or 1,
                                (t.reason or "")[:160],
                                f"Replay the shrunk sequence from {reporter.REPORT_FILE}, fix the accounting it exposes, "
                                "and keep the replay as a regression test.", contract=t.contract))
    info = {"status": run.status, "passed": run.count(reporter.PASSED), "failed": run.count(reporter.FAILED),
            "report": str(report_md) if report_md.exists() else None, "command": " ".join(cmd[2:]), "returncode": rc,
            "tail": "".join(captured[-15:]) if not run.tests else ""}
    return info, findings, run


def simulate(target: str, presets: Iterable[int] = ALL_PRESETS, run_forge: bool = True, out_dir: str | Path | None = None,
             progress: Progress | None = None, cancel: Callable[[], bool] | None = None, ast_path: str | None = None,
             forge_timeout: float = 1800.0, opener=None) -> tuple[ScoreResult, Path]:
    """Score ``target`` (path or URL), build the preset matrix, optionally fuzz with forge, write the report."""
    progress = progress or (lambda _m: None)
    presets = frozenset(presets)
    target = target.strip()

    def check():
        if cancel and cancel():
            raise Cancelled("cancelled")

    run = None
    if is_url(target):
        progress(f"URL: one passive GET of {target}")
        result = score_url(target, presets, opener=opener)
        result.notes.append("Presets 01-08 are Solidity invariant vectors; they do not apply to a live page.")
    else:
        path = Path(target).expanduser()
        progress(f"Static pass over {path}")
        result, sol = score_path(path, presets)
        progress(f"  {result.files_scanned} file(s), {result.lines_scanned} line(s), {len(result.findings)} finding(s)")
        check()
        if sol:
            rows, note = _blueprint_matrix(path.resolve(), presets, ast_path, progress)
            if rows is None:
                rows = matrix_from_text(sol, result.findings, presets)
                result.notes.append(note)
            else:
                merge_text_flags(rows, result.findings)
            result.matrix = rows
            check()
            root = _foundry_root(path.resolve())
            if run_forge and root and shutil.which("forge"):
                info, broken, run = _run_forge(root, progress, cancel, forge_timeout)
                result.forge = info
                result.findings += broken
                result.score = score(result.findings)
            elif run_forge:
                why = "forge is not on PATH" if not shutil.which("forge") else "no foundry.toml above the target"
                result.notes.append(f"Fuzzing skipped: {why}. ARMED cells show the suites `foundryguard run --test` "
                                    "would generate and run.")
    check()
    out = Path(out_dir).expanduser() if out_dir else default_report_dir(target)
    out.mkdir(parents=True, exist_ok=True)
    page = out / reporter.HTML_FILE
    page.write_text(render_html(result, run), encoding="utf-8")
    (out / SCORE_JSON).write_text(json.dumps(result.as_dict(), indent=2) + "\n", encoding="utf-8")
    progress(f"Score {result.score}/100 ({result.verdict}); report: {page}")
    return result, page


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

SCORE_CSS = """
.scorebox { display: flex; align-items: stretch; border: 2px solid #111; margin: 0 0 20px; }
.scorebox .num { background: #111; color: #fff; font-size: 44px; font-weight: 700; line-height: 1; padding: 18px 22px;
                 min-width: 150px; text-align: center; }
.scorebox .num small { font-size: 14px; font-weight: 400; color: #bbb; }
.scorebox .meta { padding: 12px 16px; display: flex; flex-direction: column; justify-content: center; gap: 2px; }
.scorebox .verdict { font-size: 16px; font-weight: 700; letter-spacing: 1px; }
.sev { display: inline-block; padding: 0 6px; font-size: 11px; font-weight: 700; line-height: 18px; color: #fff; }
.sev.CRITICAL { background: #111; } .sev.HIGH { background: #444; } .sev.MEDIUM { background: #777; }
.sev.LOW { background: #e0e0e0; color: #111; }
td.cell { text-align: center; white-space: nowrap; } td.ARMED { background: #111; color: #fff; font-weight: 700; }
td.FLAGGED { background: #666; color: #fff; } td.off { color: #aaa; }
td.loc { white-space: nowrap; } td.ev { color: #555; word-break: break-word; }
ol.plan li { margin: 6px 0; }
"""


def _h(v) -> str:
    return _html.escape(str(v), quote=True)


def _md(v) -> str:
    """Escaped text with `code` spans."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _h(v))


def _pts(f: Finding) -> str:
    return f"-{f.points}" if f.points else "0 (cap)"


def render_html(result: ScoreResult, run=None, generated: str | None = None) -> str:
    generated = generated or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = result.counts()
    out = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>FoundryGuard Report</title><style>{reporter.HTML_CSS}{SCORE_CSS}</style></head><body><main>",
           f'<div class="scorebox" id="score"><div class="num">{result.score}<small>/100</small></div>'
           f'<div class="meta"><span class="verdict">{_h(result.verdict)}</span>'
           f"<span>{_h(result.target)}</span>"
           f'<span class="muted">{len(result.findings)} deduction(s): '
           + ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES)
           + "</span></div></div>",
           "<h1>FoundryGuard Security Simulation</h1>",
           f'<p class="sub">Generated {_h(generated)}. Target kind: {_h(result.kind)}. '
           f"{result.files_scanned} file(s), {result.lines_scanned} line(s) read. "
           f"Presets on: {_h(', '.join(f'{p:02d}' for p in result.presets) or 'none')}.</p>"]
    for n in result.notes:
        out.append(f'<p class="muted">{_h(n)}</p>')

    out.append("<h2>Scoring</h2>")
    out.append(f"<p>Start at 100. CRITICAL -{WEIGHTS['CRITICAL']}, HIGH -{WEIGHTS['HIGH']}, MEDIUM -{WEIGHTS['MEDIUM']}, "
               f"LOW -{WEIGHTS['LOW']}; one rule takes at most {RULE_CAP}x its weight; the floor is 1.</p>")
    out.append('<table><tr><th>Layer</th><th class="n">Findings</th><th class="n">Points</th></tr>')
    for lid, name in LAYERS.items():
        fs = [f for f in result.findings if f.layer == lid]
        if fs:
            out.append(f'<tr><td>{lid} {_h(name)}</td><td class="n">{len(fs)}</td><td class="n">-{sum(f.points for f in fs)}</td></tr>')
    out.append(f'<tr><th>Total</th><th class="n">{len(result.findings)}</th>'
               f'<th class="n">-{sum(f.points for f in result.findings)}</th></tr></table>')

    out.append("<h2>Deductions</h2>")
    if not result.findings:
        out.append("<p>No deductions. A clean static pass is not proof of safety; it means none of the rules matched.</p>")
    else:
        out.append('<div class="scroll"><table><tr><th>#</th><th>Severity</th><th>Layer</th><th>Rule</th><th>Location</th>'
                   '<th class="n">Points</th><th>Finding</th></tr>')
        for i, f in enumerate(result.findings, 1):
            ev = f'<br><code class="muted">{_h(f.evidence)}</code>' if f.evidence else ""
            out.append(f'<tr><td class="n">{i}</td><td><span class="sev {f.severity}">{f.severity}</span></td>'
                       f"<td>{f.layer} {_h(LAYERS[f.layer])}</td><td>{_h(f.rule)}</td>"
                       f'<td class="loc">{_h(f.location)}</td><td class="n">{_pts(f)}</td>'
                       f'<td class="ev">{_md(f.title)}{ev}</td></tr>')
        out.append("</table></div>")

        out.append("<h2>Mitigation plan</h2><ol class=\"plan\">")
        by_rule: dict[str, list[Finding]] = {}
        for f in result.findings:
            by_rule.setdefault(f.rule, []).append(f)
        for rule, fs in by_rule.items():
            locs = ", ".join(f.location for f in fs[:12]) + (f" and {len(fs) - 12} more" if len(fs) > 12 else "")
            out.append(f'<li><span class="sev {fs[0].severity}">{fs[0].severity}</span> <b>{_h(rule)}</b>: '
                       f"{_md(fs[0].mitigation)}<br><span class=\"muted\">at {_h(locs)}</span></li>")
        out.append("</ol>")

    if result.matrix:
        out.append("<h2>Simulation matrix</h2>")
        src = "solc AST (the same detectors `foundryguard gen` uses)" if any(r.source == "ast" for r in result.matrix) \
            else "source-level detectors"
        out.append(f'<p class="muted">From the {src}. ARMED: the preset generates an invariant suite for this contract. '
                   "FLAGGED: a scoring rule for this preset matched. off: switched off for this run.</p>")
        out.append('<div class="scroll"><table><tr><th>Contract</th><th>File</th>'
                   + "".join(f'<th class="n" title="{_h(PRESETS[p])}">{p:02d}</th>' for p in PRESETS) + "</tr>")
        for r in result.matrix:
            out.append(f"<tr><td>{_h(r.contract)}</td><td>{_h(r.file)}</td>"
                       + "".join(f'<td class="cell {r.cells[p]}">{_h(r.cells[p])}</td>' for p in PRESETS) + "</tr>")
        out.append("</table></div>")
        out.append("<p class=\"muted\">" + "; ".join(f"{p:02d} {_h(n)}" for p, n in PRESETS.items()) + "</p>")

    if result.forge:
        fz = result.forge
        out.append("<h2>Fuzz campaign</h2>")
        out.append(f"<p><code>{_h(fz['command'])}</code>: {_h(fz['status'])}, {fz['passed']} passed, {fz['failed']} failed"
                   + (f"; full report in <code>{_h(fz['report'])}</code>" if fz.get("report") else "") + ".</p>")
        if fz.get("tail"):
            out.append(f"<pre>{_h(fz['tail'])}</pre>")
        if run is not None and getattr(run, "tests", None):
            out += reporter.html_sections(run, Path(result.target) if Path(result.target).is_dir() else Path(result.target).parent)

    out.append("<footer>Generated by FoundryGuard. The score is a strict static measure plus any invariants forge broke; "
               "a high score is not an audit.</footer></main></body></html>")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_presets(text: str | None) -> frozenset[int]:
    if not text or text.strip().lower() == "all":
        return ALL_PRESETS
    if text.strip().lower() == "none":
        return frozenset()
    out = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n not in PRESETS:
            raise ValueError(f"unknown preset {part} (1-8)")
        out.add(n)
    return frozenset(out)


def add_score_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("target", help="project dir, a single file, or an http(s) URL (one passive GET)")
    ap.add_argument("--presets", default="all", help="comma list of preset ids 1-8, 'all' or 'none' (default: all)")
    ap.add_argument("--fuzz", action="store_true", help="also run forge on the generated suites when forge is on PATH")
    ap.add_argument("--out", help="report directory (default: the project dir; ~/foundryguard-reports/<host> for a URL)")
    ap.add_argument("--ast", help="use a prebuilt solc Standard JSON output for the preset matrix")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--min-score", type=int, default=0, help="exit 1 when the score is below this")


def cmd_score(args) -> int:
    try:
        presets = parse_presets(args.presets)
    except ValueError as exc:
        print(f"foundryguard: {exc}", file=sys.stderr)
        return 2
    try:
        result, page = simulate(args.target, presets, run_forge=args.fuzz, out_dir=args.out, ast_path=args.ast,
                                progress=lambda m: print("foundryguard: " + m, file=sys.stderr))
    except (FileNotFoundError, urllib.error.URLError, OSError, ValueError) as exc:
        print(f"foundryguard: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"{result.score}/100 {result.verdict}  {len(result.findings)} deduction(s)  {page}")
        for f in result.findings[:20]:
            print(f"  -{f.points:<3} {f.severity:<8} {f.layer:<3} {f.rule:<26} {f.location}  {f.title}")
        if len(result.findings) > 20:
            print(f"  ... {len(result.findings) - 20} more in the report")
    return 1 if result.score < args.min_score else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="foundryguard-score", description="Score a codebase or page from 1 to 100.")
    add_score_args(ap)
    return cmd_score(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
