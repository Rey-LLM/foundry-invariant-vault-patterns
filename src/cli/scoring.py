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
* The bridge between them (Layer 12, ``web_surface.py``): where the backend signs with a server key, sends
  transactions, allocates nonces or trusts RPC answers, paired with the contract function that verifies
  the signature. Typehash and domain drift, replayable or never-expiring signatures, public signing routes
  and leaked keys land under layer L11.
* The signature database (Layer 13, ``signatures.py``): 150 named signatures, FG-01..FG-50 and FG-104..FG-125
  for contracts, FG-51..FG-103 and FG-126..FG-150 for backend code, response headers, dependency manifests,
  WebSockets, sessions and the bridge, each with a fixed severity, a CWE/SWC reference and a fix example. Matching findings carry the signature id;
  ``foundryguard.toml`` ``[score]`` can retune severities, ignore paths and limit how deep the walk goes.
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
from typing import Callable, Iterable, Iterator

if __package__:
    from . import reporter, signatures
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import reporter  # type: ignore
    import signatures  # type: ignore

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
    "L11": "web2-web3 bridge",
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
USER_AGENT = "FoundryGuard/0.16 (passive single-page check)"
CONFIG_FILE = "foundryguard.toml"
SCORE_JSON = "foundryguard-score.json"
FINDINGS_LOG = "foundryguard-findings.log"


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
    signature: str | None = None  # FG-xx when the rule is in the Layer 13 signature database
    fix: str | None = None  # fix example from the signature database

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
    bridge: dict | None = None  # web_surface.BridgeReport.as_dict(), when the target has a web2-web3 seam

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


# One pass of a compiled tokenizer instead of a Python loop over every character. The leftmost token wins, the
# same way the old scanner worked: a quote inside a comment is comment, a // inside a string is string.
_STRIP_BASE = (r"(?P<c>//[^\n]*|/\*[\s\S]*?(?:\*/|\Z))"
               r"|(?P<q>[\"'])(?P<b>(?:\\[\s\S]|(?!(?P=q))[^\\\n])*)(?P<e>(?P=q))?")
_STRIP_TOKENS = re.compile(_STRIP_BASE)
_STRIP_TOKENS_TPL = re.compile(_STRIP_BASE + r"|(?P<t>`)(?P<tb>(?:\\[\s\S]|[^`\\])*)(?P<te>`)?")
_NOT_NL = re.compile(r"[^\n]")


def strip_comments(text: str, blank_strings: bool = True, templates: bool = False) -> str:
    """Comments (and string contents) replaced by spaces; offsets and newlines are kept.

    ``templates`` also treats JavaScript backtick literals as strings, so a ``//`` inside a template (a URL) is not
    taken for a comment.
    """
    def sub(m: re.Match) -> str:
        if m.group("c") is not None:
            return _NOT_NL.sub(" ", m.group("c"))
        if not blank_strings:
            return m.group(0)
        if m.group("q") is not None:
            return m.group("q") + _NOT_NL.sub(" ", m.group("b")) + (m.group("e") or "")
        return "`" + _NOT_NL.sub(" ", m.group("tb")) + (m.group("te") or "")

    return (_STRIP_TOKENS_TPL if templates else _STRIP_TOKENS).sub(sub, text)


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
WEAK_RANDOM = re.compile(r"keccak256\s*\([^;]*\b(block\.timestamp|block\.prevrandao|block\.difficulty|blockhash|block\.number)\b|"
                         r"\b(block\.timestamp|block\.prevrandao|block\.difficulty|block\.number|blockhash\s*\([^)]*\))\s*%")
ERC20_CALL = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*(?:\s*\([^()]*\))?(?:\s*\[[^\]]*\])?)\s*\.\s*(transfer|transferFrom|approve)\s*\(")
TRANSFER_FROM = re.compile(r"\.\s*(transferFrom|safeTransferFrom)\s*\(\s*([A-Za-z_$][\w$]*)\s*,")
STORAGE_LOOP = re.compile(r"\bfor\s*\([^;]*;[^;]*<=?\s*([A-Za-z_$][\w$]*)\s*\.\s*length\s*;")
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


# --------------------------------------------------------------------------- #
# Solidity signatures added with the 103-signature database (FG-10, 15, 17, 21-25, 27, 29, 35-44, 47, 48)
# --------------------------------------------------------------------------- #

TWAP_CALL = re.compile(r"\b(consult|observe|getTwap\w*|twap\w*|getTimeWeighted\w*|getArithmeticMeanTick\w*)\s*\(", re.I)
TWAP_CONST = re.compile(r"\b(\w*(?:twap|period|window|seconds_?ago|observation)\w*)\s*=\s*(\d+)\s*(seconds|minutes|hours)?\s*;", re.I)
TWAP_SECONDS_AGO = re.compile(r"secondsAgos?\s*\[\s*0\s*\]\s*=\s*(\d+)\s*(seconds|minutes|hours)?", re.I)
TIME_UNIT = {None: 1, "seconds": 1, "minutes": 60, "hours": 3600}
TWAP_MIN = 1800
VIEW_GUARD = re.compile(r"_reentrancyGuardEntered|nonReentrantView|_status\b|\blocked\b|_locked\b|reentrancyLock", re.I)
TS_EQ = re.compile(r"block\.(timestamp|number)\s*(?:==|!=)\s*([A-Za-z_][\w.]*)|([A-Za-z_][\w.]*)\s*(?:==|!=)\s*block\.(timestamp|number)")
TS_TARGET = re.compile(r"start|end|deadline|expir|unlock|open|close|launch|release|vest|matur|time|epoch", re.I)
NATIVE_ONE_ARG = re.compile(r"(payable\s*\((?:[^()]|\([^()]*\))*\)|[A-Za-z_$][\w$]*(?:\[[^\]]*\])?)\s*\.\s*(transfer|send)\s*\(")
FIXED_GAS = re.compile(r"\{[^}]*\bgas\s*:\s*\d+[^}]*\}\s*\(")
LOOP_HEAD = re.compile(r"\b(for|while)\s*\(")
NATIVE_PAY = re.compile(r"\.\s*(transfer|send)\s*\(\s*[^,()]*(?:\([^()]*\))?[^,()]*\)|\{\s*value\s*:|\bsendValue\s*\(|safeTransferETH\s*\(")
SLIPPAGE_ZERO = re.compile(
    r"\b(amountOutMin(?:imum)?|minAmountOut|minOut|minReturn\w*|min_dy|amountAMin|amountBMin|minDy|minAmountsOut)\s*:\s*0\s*[,})]|"
    r"\b(swapExactTokensFor\w*|swapExactETHFor\w*|swapTokensForExact\w*)\s*(?:\{[^}]*\})?\s*\(\s*(?:[^,()]+(?:\([^()]*\))?\s*,\s*)?0\s*,|"
    r"\bexchange(?:_underlying)?\s*\(\s*[^,()]+,\s*[^,()]+,\s*[^,()]+(?:\([^()]*\))?\s*,\s*0\s*\)")
DEADLINE_NOW = re.compile(r"\bdeadline\s*:\s*block\.timestamp\s*[,})]|"
                          r"\b(swap\w*|addLiquidity\w*|removeLiquidity\w*)\s*(?:\{[^}]*\})?\s*\([^;]*?,\s*block\.timestamp\s*\)")
DOWNCAST = re.compile(r"(?<![\w.$])(u?int)(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|168|176|184|192|"
                      r"200|208|216|224|232|240|248)\s*\(")
SIG_AS_KEY = re.compile(r"\[\s*(sig\w*|signature\w*)\s*\]|keccak256\s*\(\s*(abi\.encodePacked\s*\(\s*)?"
                        r"(sig\w*|signature\w*|v\s*,\s*r\s*,\s*s|r\s*,\s*s\s*,\s*v)\s*\)", re.I)
S_UPPER_BOUND = re.compile(r"0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", re.I)
SLOT_DEF = re.compile(r"(?:bytes32\s+(?:(?:internal|private|public|constant|immutable)\s+)*)?([A-Za-z_]\w*)\s*=\s*keccak256\s*\(\s*"
                      r"(?:abi\.encodePacked\s*\(\s*|bytes\s*\(\s*)?\"([^\"]+)\"")


def _contract_header(sf: _SolFile, c: SolContract) -> str:
    i = sf.clean.rfind(c.name, 0, c.start)
    return sf.clean[i:c.start] if i >= 0 else ""


def _inherited_names(sf: _SolFile) -> set[str]:
    names: set[str] = set()
    for c in sf.contracts:
        hdr = _contract_header(sf, c)
        m = re.search(r"\bis\b(.*)$", hdr, re.S)
        if m:
            names |= set(re.findall(r"[A-Za-z_]\w*", re.sub(r"\([^()]*\)", "", m.group(1))))
    return names


def _upgradeable(sf: _SolFile, c: SolContract) -> bool:
    return bool(re.search(r"\bInitializable\b|\w+Upgradeable\b", _contract_header(sf, c))) or any(
        m in ("initializer", "reinitializer", "onlyInitializing") for f in c.functions for m in f.modifiers)


def _with_locals(sf: _SolFile, c: SolContract, fn: SolFunction) -> str:
    """The function body plus the bodies of the contract's own functions it calls (one level)."""
    body = sf.body(fn)
    called = _local_calls(sf, fn)
    return body + "".join(sf.body(o) for o in c.functions if o.name in called and o is not fn)


def _loops(body: str) -> list[tuple[int, str]]:
    out = []
    for m in LOOP_HEAD.finditer(body):
        p_close = match_close(body, m.end() - 1, "(", ")")
        rest = body[p_close + 1:]
        lead = len(rest) - len(rest.lstrip())
        if rest[lead:lead + 1] == "{":
            start = p_close + 1 + lead
            out.append((m.start(), body[start:match_close(body, start) + 1]))
        else:
            end = body.find(";", p_close)
            out.append((m.start(), body[p_close + 1:end + 1 if end >= 0 else len(body)]))
    return out


def _seconds(num: str, unit: str | None) -> int:
    return int(num) * TIME_UNIT[unit.lower() if unit else None]


def solidity_pack_fn(sf: _SolFile, c: SolContract, fn: SolFunction, add, authorized: bool) -> None:
    body = sf.body(fn)
    b0 = fn.body_start
    cname = c.name

    def hit(rule, title, off, mitigation=None, preset=None, is_line=False):
        sig = signatures.lookup(rule)
        add(rule, signatures.severity(rule), _SIG_LAYER.get(rule, "L4"), title, off,
            mitigation or sig.mitigation, preset=preset, contract=cname, is_line=is_line)

    # FG-17 oracle answer never checked > 0
    for m in LATEST_ROUND.finditer(body):
        stmt = body[max(body.rfind(";", 0, m.start()), body.rfind("{", 0, m.start())) + 1:m.start()]
        nm = re.search(r"\bint\d*\s+([A-Za-z_]\w*)", stmt)
        if not nm:
            continue
        v = re.escape(nm.group(1))
        if not re.search(rf"\b{v}\s*(<=|<|>|>=|==|!=)\s*0\b|\b0\s*(<|>=|>|<=|==|!=)\s*{v}\b|toUint256\s*\(\s*{v}\s*\)", body):
            hit("SOL-ORACLE-BAD-PRICE", f"`{nm.group(1)}` from `latestRoundData` is used without an `> 0` check",
                b0 + m.start(), preset=6)

    # FG-15 TWAP call with a literal short window
    for m in TWAP_CALL.finditer(body):
        close = match_close(body, m.end() - 1, "(", ")")
        args = _split_args_sol(body[m.end():close])
        if args:
            lm = re.fullmatch(r"(?:uint32\s*\(\s*)?(\d+)\s*(seconds|minutes|hours)?\s*\)?", args[-1].strip())
            if lm and 0 < _seconds(lm.group(1), lm.group(2)) < TWAP_MIN:
                hit("SOL-TWAP-SHORT-WINDOW", f"`{m.group(1)}` over {_seconds(lm.group(1), lm.group(2))} s",
                    b0 + m.start(), preset=6)
    for m in TWAP_SECONDS_AGO.finditer(body):
        if 0 < _seconds(m.group(1), m.group(2)) < TWAP_MIN:
            hit("SOL-TWAP-SHORT-WINDOW", f"TWAP observation window of {_seconds(m.group(1), m.group(2))} s",
                b0 + m.start(), preset=6)

    # FG-22 UUPS upgrade authorization left empty
    if fn.name == "_authorizeUpgrade" and re.fullmatch(r"\{\s*\}", body) and not fn.modifiers:
        hit("SOL-UUPS-NO-AUTH", "`_authorizeUpgrade` is empty and has no modifier: anyone can upgrade",
            fn.line, preset=None, is_line=True)

    # FG-27 caller picks target and calldata
    if fn.exposed and fn.kind == "function" and fn.state_changing and not authorized:
        addr = {p[1] for p in fn.params if p[0] in ("address", "address[]") and p[1]}
        data = {p[1] for p in fn.params if p[0] in ("bytes", "bytes[]") and p[1]}
        if addr and data:
            pat = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\[[^\]]*\])?\s*\.\s*(call|functionCall\w*)\s*"
                             r"(?:\{[^}]*\})?\s*\(\s*([A-Za-z_$][\w$]*)|"
                             r"functionCall\w*\s*\(\s*([A-Za-z_$][\w$]*)(?:\s*\[[^\]]*\])?\s*,\s*([A-Za-z_$][\w$]*)")
            for m in pat.finditer(body):
                target, payload = (m.group(1), m.group(3)) if m.group(1) else (m.group(4), m.group(5))
                if target in addr and payload in data:
                    hit("SOL-ARBITRARY-CALL", f"`{fn.name}` calls `{target}` with `{payload}`, both chosen by the caller",
                        b0 + m.start())
                    break

    # FG-29 malleable ecrecover, only where the signature itself is the replay key (a nonce makes it harmless)
    m = re.search(r"\becrecover\s*\(", full_body := _with_locals(sf, c, fn))
    if m and "ecrecover" in body and not S_UPPER_BOUND.search(sf.clean) and SIG_AS_KEY.search(full_body):
        hit("SOL-SIG-MALLEABLE", f"`{fn.name}` keys replay protection on the signature bytes and uses raw `ecrecover`",
            b0 + body.find("ecrecover"))

    # FG-35 timestamp equality
    for m in TS_EQ.finditer(body):
        other = m.group(2) or m.group(3) or ""
        if TS_TARGET.search(other) and not re.search(r"last|updated|prev|current", other, re.I):
            hit("SOL-TIMESTAMP-EQUALITY", f"`block.{m.group(1) or m.group(4)}` compared for equality with `{other}`",
                b0 + m.start())
            break

    # FG-36 fixed gas stipend
    for m in NATIVE_ONE_ARG.finditer(body):
        close = match_close(body, m.end() - 1, "(", ")")
        if len(_split_params(body[m.end():close])) == 1 and m.group(1) not in ("super", "this"):
            hit("SOL-GAS-STIPEND", f"Ether sent with `.{m.group(2)}` (2300 gas stipend)", b0 + m.start())
            break
    else:
        m = FIXED_GAS.search(body)
        if m:
            hit("SOL-GAS-STIPEND", "External call with a hard-coded gas amount", b0 + m.start())

    # FG-37 hand-decoded calldata
    m = re.search(r"\bcalldataload\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", body)
    if m and int(m.group(1), 0) >= 4 and not re.search(r"calldatasize|msg\.data\.length", sf.clean[c.start:c.end]):
        hit("SOL-SHORT-CALLDATA", f"`{fn.name}` reads calldata at fixed offsets and never checks its length",
            b0 + m.start())

    full = _with_locals(sf, c, fn)
    # FG-38 order filled without state checks
    if fn.exposed and fn.state_changing and re.match(r"^_?(fill|execute|match|take|settle)\w*order", fn.name, re.I) and \
            any("order" in (p[0] + p[1]).lower() for p in fn.params) and \
            not re.search(r"filled|cancel|status|isValid|validat|verify|used|executed|remaining|nonce|invalidat", full, re.I):
        hit("SOL-DIRTY-ORDER", f"`{fn.name}` fills an order without checking filled/cancelled state or a nonce",
            fn.line, is_line=True)

    # FG-39 / FG-40 swap protection
    m = SLIPPAGE_ZERO.search(body)
    if m:
        hit("SOL-SLIPPAGE-ZERO", "Swap with a minimum output of 0", b0 + m.start())
    m = DEADLINE_NOW.search(body)
    if m:
        hit("SOL-DEADLINE-NOW", "Swap deadline is `block.timestamp`", b0 + m.start())

    # FG-41 / FG-42 governance tallies
    if fn.exposed and re.match(r"^(castVote\w*|vote\w*)$", fn.name) and re.search(r"\+=|\+\+", full) and \
            not re.search(r"hasVoted|voted|receipt|alreadyVoted|hasCast|ballot", full, re.I):
        hit("SOL-VOTE-DOUBLE-COUNT", f"`{fn.name}` adds to the tally with no has-voted check", fn.line,
            preset=7, is_line=True)
    if fn.exposed and re.match(r"^delegate(BySig)?$", fn.name) and re.search(r"\+=", full) and not re.search(r"-=", full):
        hit("SOL-DELEGATE-INFLATION", f"`{fn.name}` adds votes to the new delegate and never removes them from the old one",
            fn.line, preset=7, is_line=True)

    # FG-43 / FG-44 loops
    for off, block in _loops(body):
        if fn.exposed and fn.state_changing and NATIVE_PAY.search(block):
            hit("SOL-ETH-PUSH-LOOP", f"`{fn.name}` sends ether to every entry of a loop", b0 + off)
            break
    for off, block in _loops(body):
        if "msg.value" in block:
            hit("SOL-MSG-VALUE-LOOP", f"`msg.value` read inside a loop in `{fn.name}`", b0 + off)
            break
    else:
        if fn.mutability == "payable" and re.search(r"address\s*\(\s*this\s*\)\s*\.\s*delegatecall", body):
            m = re.search(r"delegatecall", body)
            hit("SOL-MSG-VALUE-LOOP", f"payable `{fn.name}` delegatecalls into itself (msg.value reused per call)",
                b0 + m.start())

    # FG-47 downcast of a caller-supplied 256-bit value with no bound in sight
    if fn.exposed and fn.kind == "function" and not re.search(r"\bSafeCast\w*\b", sf.clean):
        wide = {p[1] for p in fn.params if p[0] in ("uint256", "int256", "uint", "int") and p[1]}
        for m in DOWNCAST.finditer(body):
            close = match_close(body, m.end() - 1, "(", ")")
            arg = body[m.end():close].strip()
            if arg not in wide:
                continue
            if re.search(rf"(?<![\w.$]){re.escape(arg)}\s*(<=?|>=?)|(<=?|>=?)\s*{re.escape(arg)}\b", body):
                continue
            hit("SOL-UNSAFE-DOWNCAST", f"`{m.group(1)}{m.group(2)}({arg})` truncates the caller's value silently",
                b0 + m.start())
            break


def _split_args_sol(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur)
    return out


def solidity_pack_contract(sf: _SolFile, c: SolContract, add, inherited: set[str]) -> None:
    cname = c.name
    text = sf.clean[c.start:c.end]

    def hit(rule, title, off, preset=None, is_line=False):
        add(rule, signatures.severity(rule), _SIG_LAYER.get(rule, "L4"), title, off,
            signatures.lookup(rule).mitigation, preset=preset, contract=cname, is_line=is_line)

    # FG-10 read-only reentrancy
    late: dict[str, str] = {}
    for fn in c.functions:
        if not (fn.exposed and fn.state_changing and fn.kind == "function"):
            continue
        body = sf.body(fn)
        calls = list(EXTERNAL_CALL.finditer(body)) + list(LOW_LEVEL_CALL.finditer(body))
        if calls:
            first = fn.body_start + min(m.start() for m in calls)
            for off, var in sf.writes(c, fn.body_start, fn.body_end):
                if off > first:
                    late.setdefault(var, fn.name)
    if late:
        for fn in c.functions:
            if not (fn.exposed and fn.kind == "function" and fn.mutability == "view"):
                continue
            body = sf.body(fn)
            used = [v for v in late if re.search(rf"(?<![\w.$]){re.escape(v)}\b", body)]
            if used and not VIEW_GUARD.search(body) and not any(REENTRANCY_GUARDS.match(m) or "nonReentrant" in m
                                                               for m in fn.modifiers):
                hit("SOL-READONLY-REENTRANCY",
                    f"`{fn.name}` returns `{used[0]}`, which `{late[used[0]]}` updates after an external call",
                    fn.line, preset=8, is_line=True)

    # FG-15 TWAP window constants
    if TWAP_CALL.search(text):
        for m in TWAP_CONST.finditer(sf.clean, c.start, c.end):
            secs = _seconds(m.group(2), m.group(3))
            if 0 < secs < TWAP_MIN:
                hit("SOL-TWAP-SHORT-WINDOW", f"TWAP window `{m.group(1)}` is {secs} s", c.start + (m.start() - c.start), preset=6)

    if c.kind == "interface" or c.kind == "library":
        return
    upgradeable = _upgradeable(sf, c)
    mutable_vars = [(v, meta) for v, meta in c.state_vars.items() if meta["mutable"] and not meta.get("transient")]
    # FG-21 implementation never locks its initializers
    public_init = any(f.exposed and any(m in ("initializer", "reinitializer") for m in f.modifiers) for f in c.functions)
    if c.kind == "contract" and upgradeable and public_init and c.name not in inherited \
            and not re.search(r"_disableInitializers\s*\(", text):
        hit("SOL-IMPL-NOT-DISABLED", f"`{cname}` is upgradeable and its constructor never calls `_disableInitializers()`",
            c.line, is_line=True)
    # FG-23 proxy with its own storage
    if any(f.kind == "fallback" for f in c.functions) and "delegatecall" in text and mutable_vars:
        v, meta = mutable_vars[0]
        hit("SOL-PROXY-STORAGE-COLLISION", f"Delegating proxy `{cname}` stores `{v}` in an ordinary slot",
            meta["line"], is_line=True)
    # FG-25 storage gap
    raw_text = sf.raw[c.start:c.end]
    if upgradeable and (c.kind == "abstract contract" or c.name in inherited) and mutable_vars \
            and "__gap" not in text and not re.search(r"erc7201|storage-location", raw_text, re.I):
        hit("SOL-STORAGE-GAP", f"Upgradeable base `{cname}` has state but no `__gap`", c.line, is_line=True)


def solidity_pack_file(sf: _SolFile, add) -> None:
    # FG-48 compiler without checked arithmetic
    pm = re.search(r"pragma\s+solidity\s+([^;]+);", sf.clean)
    if not pm:
        return
    spec = pm.group(1)
    minors = [int(x) for x in re.findall(r"0\.(\d+)", spec)]
    open_ended = re.search(r">", spec) and not re.search(r"<", spec)  # ">=0.5.0" also compiles under 0.8
    if minors and max(minors) < 8 and not open_ended and not re.search(r"\b\w*SafeMath\b|\.\s*(add|sub|mul)\s*\(", sf.clean):
        for c in sf.contracts:
            for fn in c.functions:
                if re.search(r"[\w)\]]\s*(?:[-+*]|\+=|-=|\*=)\s*[\w(]", sf.body(fn).replace("++", "").replace("--", "")):
                    add("SOL-NO-OVERFLOW-CHECKS", signatures.severity("SOL-NO-OVERFLOW-CHECKS"), "L4",
                        f"`pragma solidity {pm.group(1).strip()}` has no overflow checks and the code does arithmetic "
                        "without SafeMath", line_of(sf.clean, pm.start()),
                        signatures.lookup("SOL-NO-OVERFLOW-CHECKS").mitigation, is_line=True)
                    return


def diamond_slots(sol_files: list[tuple[str, str]]) -> list[Finding]:
    """FG-24: the same storage namespace string hashed under two different names (across all .sol files)."""
    seen: dict[str, list[tuple[str, str, int, str]]] = {}
    for rel, raw in sol_files:
        text = strip_comments(raw, blank_strings=False)
        lines = raw.splitlines()
        for m in SLOT_DEF.finditer(text):
            ns = m.group(2)
            if ns.lower().startswith("eip1967."):
                continue
            ln = line_of(text, m.start())
            seen.setdefault(ns, []).append((rel, m.group(1), ln, snippet(lines, ln)))
    out = []
    for ns, defs in seen.items():
        names = []
        for rel, name, ln, ev in defs:
            if name not in names:
                names.append(name)
                if len(names) > 1:
                    out.append(Finding("SOL-DIAMOND-SLOT-REUSE", signatures.severity("SOL-DIAMOND-SLOT-REUSE"), "L4",
                                       f"`{name}` and `{names[0]}` both hash \"{ns}\" (same storage slot)", rel, ln, ev,
                                       signatures.lookup("SOL-DIAMOND-SLOT-REUSE").mitigation))
    return out


# --------------------------------------------------------------------------- #
# Solidity signatures added in 0.16 (FG-104..FG-125): staking and rewards, timelocks, emergency exits, NFTs
# --------------------------------------------------------------------------- #

STAKE_FN = re.compile(r"^_?(stake|deposit|lock|bond)\w*$", re.I)
UNSTAKE_FN = re.compile(r"^(unstake|withdraw|redeem|exit|unbond|unlock|leave)\w*$", re.I)
# lock periods and unlock times, not reentrancy flags (`locked`, `_status`)
LOCK_VAR = re.compile(r"lock(ed)?_?(period|duration|time|until|up|end|days|secs|seconds|at)|lockup|unlock\w*|cooldown|unbond\w*|"
                      r"min_?stake\w*|minimum_?stake\w*|staking_?period|stake_?duration|min_?duration|vesting_?period|"
                      r"^_?LOCK$|^_?LOCK_\w+", re.I)
LOCK_MODIFIER = re.compile(r"lock|cooldown|after|matur|unlocked|vested", re.I)
TIME_READ = re.compile(r"\bblock\s*\.\s*(timestamp|number)\b|\bclock\s*\(|\b_now\s*\(|\b_blockTimestamp\s*\(")
REWARD_ACC = re.compile(r"^_?(rewardPerTokenStored|rewardPerToken\w*Stored|accRewardPerShare|accRewardPerToken|accRewardsPerShare|"
                        r"accTokenPerShare|rewardPerShare\w*|rewardIndex|globalIndex|cumulativeRewardPerToken)$")
BALANCE_VAR = re.compile(r"^_?(balances?|balanceOf|stakes?|staked\w*|stakeOf|userInfo|users|deposits?|totalSupply|"
                         r"totalStaked|totalDeposits?|totalShares|shares)$")
REWARD_SYNC = re.compile(r"update\w*reward|_?update\w*|accrue\w*|_checkpoint\w*|checkpoint|harvest|updatePool|_settle\w*|"
                         r"_claim\w*|_distribute\w*|_earn\w*", re.I)
SCALE = re.compile(r"\b1e\d+\b|\b10\s*\*\*\s*\d+|PRECISION|SCALE|\bWAD\b|\bRAY\b|\bether\b|MULTIPLIER|\bUNIT\b|\bONE\b|"
                   r"mulDiv|mulWad|divWad|FixedPoint|\bQ\d+\b", re.I)
REWARD_WORD = re.compile(r"reward|distribut|dividend|yield|payout|airdrop", re.I)
LOOP_PRORATA = re.compile(r"(\+=|[Tt]ransfer\w*\s*\(|sendValue\s*\()[^;]*/")
PAYS_REWARD = re.compile(r"reward\w*Token\w*\s*\.\s*(safe)?[Tt]ransfer|\bearned\s*\(|(?<![\w.])_?(getReward|claim\w*|harvest)\s*\(")
ZEROES = re.compile(r"=\s*0\s*;|\bdelete\s+\w")
RESCUE_FN = re.compile(r"^(rescue|sweep|recover|withdrawStuck|withdrawToken|withdrawERC20|recoverERC20|emergencyToken|skim|"
                       r"inCaseTokensGetStuck|salvage)\w*$", re.I)
STAKE_TOKEN_VAR = re.compile(r"stak\w*token|deposit\w*token|^stakingToken$|^asset$|^_asset$|^underlying$|^want$|^lpToken$|"
                             r"^stakeToken$|^token$", re.I)
FEE_SETTER = re.compile(r"^set\w*(fee|tax|penalty|commission|royalt)\w*$", re.I)
TIMELOCK_WORDS = re.compile(r"timelock|TimelockController|\beta\b|delay|pending[A-Z_]\w*|queue|schedule", re.I)
EXECUTE_FN = re.compile(r"^execute\w*$", re.I)
ETA_WORDS = re.compile(r"\beta\b|readyAt|executableAt|queuedAt|readyTime|executeAfter", re.I)
QUEUE_WORDS = re.compile(r"\b(queue\w*|schedule\w*|propose\w*)\s*\(", re.I)
DELAY_CONST = re.compile(r"\b(\w*[Dd]elay\w*|\w*DELAY\w*)\s*=\s*(\d+)\s*(seconds|minutes|hours|days|weeks)?\s*;")
UNIT_SECS = {None: 1, "seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}
SAFE_HOOK = re.compile(r"(?<![\w.$])(_safeMint|_safeTransfer|_mintBatch|_safeBatchTransferFrom)\s*\(|"
                       r"\.\s*(safeBatchTransferFrom)\s*\(|"
                       r"(?<![\w$])(\w*(?:nft|NFT|Nft|erc721|ERC721|erc1155|ERC1155|collection|Collection|items|Items)\w*)\s*"
                       r"(?:\)\s*)?\.\s*safeTransferFrom\s*\(")
NFT_OUT = re.compile(r"(?:safeTransferFrom|transferFrom)\s*\(\s*address\s*\(\s*this\s*\)\s*,\s*([A-Za-z_][\w.]*)")
STAKER_MAP = re.compile(r"staker|owner|depositor|stakedBy|tokenOwner|holder", re.I)
SUPPLY_MAP = re.compile(r"supply|minted|circulating", re.I)
CLAIM_FN = re.compile(r"^(claim\w*|getReward\w*|harvest\w*|withdrawReward\w*|collect\w*)$", re.I)
OWED_READ = re.compile(r"\b(\w*(?:reward|Reward|earned|Earned|pending|Pending|claimable|Claimable|owed|Owed|accrued|Accrued)\w*)"
                       r"\s*\[\s*(?:msg\.sender|_msgSender\(\s*\)|account|user|to)\s*\]")
PAYOUT = re.compile(r"[Tt]ransfer\w*\s*\(|\.\s*call\s*\{|sendValue\s*\(|safeTransferETH\s*\(|\._mint\s*\(|(?<![\w.])_mint\s*\(")
PERIOD_VAR = re.compile(r"^(periodFinish|finishAt|periodEnd|rewardEnd\w*|endTime|finishTime|rewardsEnd\w*)$")
RATE_SET = re.compile(r"\brewardRate\s*=\s*[^;]*/")
LOCK_MAP_WRITE = r"\b(\w*(?:lock|Lock|until|Until|release|Release|cooldown|Cooldown|expir|Expir|vest|Vest)\w*)\s*\[\s*{u}\s*\]\s*=\s*[^;]*block\s*\.\s*timestamp"
VEST_FN = re.compile(r"vest|releasable|unlocked|claimable|available", re.I)
ELAPSED = re.compile(r"block\s*\.\s*timestamp\s*-\s*[\w.\[\]]+")
PER_DURATION = re.compile(r"/\s*\(?\s*[\w.]*(duration|Duration|DURATION|period|Period|PERIOD|length|Length)\w*")
TS_COMPARE = re.compile(r"block\s*\.\s*timestamp\s*[<>]|[<>]=?\s*block\s*\.\s*timestamp|\b(elapsed|timePassed|passed|dt)\w*\s*[<>]|"
                        r"\bmin\s*\(")
RECEIVER_FN = re.compile(r"^on(ERC721Received|ERC1155Received|ERC1155BatchReceived)$")
SENDER_CHECKED = re.compile(r"msg\.sender\s*(==|!=)|(==|!=)\s*msg\.sender|_msgSender\(\s*\)\s*(==|!=)|\[\s*(msg\.sender|_msgSender\(\s*\))\s*\]")


def _sol16_hit(add, cname: str):
    def hit(rule, title, off, is_line=False):
        add(rule, signatures.severity(rule), _SIG_LAYER.get(rule, "L4"), title, off,
            signatures.lookup(rule).mitigation, contract=cname, is_line=is_line)
    return hit


def _nft_contract(sf: _SolFile, c: SolContract, kind: str = "721|1155") -> bool:
    return bool(re.search(rf"\bERC({kind})\w*\b", _contract_header(sf, c)))


def solidity_pack16_fn(sf: _SolFile, c: SolContract, fn: SolFunction, add, authorized: bool) -> None:
    if fn.kind != "function":
        return
    hit = _sol16_hit(add, c.name)
    body = sf.body(fn)
    b0 = fn.body_start
    full = _with_locals(sf, c, fn)
    sv = c.state_vars
    mutating = fn.exposed and fn.state_changing

    # FG-104 unstake with no time check in a staking contract that declares a lock
    if mutating and UNSTAKE_FN.match(fn.name) and any(STAKE_FN.match(o.name) for o in c.functions):
        lock_vars = [v for v, meta in sv.items() if LOCK_VAR.search(v) and re.search(r"u?int|mapping", meta["type"])]
        if lock_vars and not TIME_READ.search(full) and not any(LOCK_MODIFIER.search(m) for m in fn.modifiers) \
                and not any(re.search(rf"(?<![\w.$]){re.escape(v)}\b", full) for v in lock_vars):
            hit("SOL-STAKE-NO-LOCK", f"`{fn.name}` releases stake without checking `{lock_vars[0]}` against the clock",
                fn.line, is_line=True)

    # FG-105 balance changes without the reward checkpoint
    if mutating and any(REWARD_ACC.match(v) for v in sv) and not re.match(r"^(notify|set|recover|rescue|sweep)", fn.name, re.I):
        bal = [(off, v) for off, v in sf.writes(c, fn.body_start, fn.body_end) if BALANCE_VAR.match(v)]
        if bal and not any(REWARD_SYNC.search(m) for m in fn.modifiers) \
                and not re.search(r"(?<![\w.$])(" + REWARD_SYNC.pattern + r")\s*\(", full, re.I):
            hit("SOL-REWARD-NOT-UPDATED", f"`{fn.name}` changes `{bal[0][1]}` without settling rewards first", bal[0][0])

    # FG-107 pro-rata reward push loop
    if mutating:
        for off, block in _loops(body):
            head = body[off:off + 200].split("{", 1)[0]
            if ".length" in head and LOOP_PRORATA.search(block) and (REWARD_WORD.search(fn.name) or REWARD_WORD.search(block)):
                hit("SOL-REWARD-LOOP-DISTRIBUTION", f"`{fn.name}` splits rewards across every entry in one loop", b0 + off)
                break

    # FG-108 emergency withdraw that pays rewards or never zeroes the position
    if mutating and re.match(r"^emergency\w*(withdraw|exit|unstake)", fn.name, re.I) and PAYOUT.search(full):
        m = PAYS_REWARD.search(full)
        if m or not ZEROES.search(full):
            why = "pays rewards" if m else "never zeroes the position"
            hit("SOL-EMERGENCY-WITHDRAW-FLAW", f"`{fn.name}` {why}", fn.line, is_line=True)

    # FG-125 emergency exit behind whenNotPaused
    if fn.exposed and re.match(r"^emergency", fn.name, re.I) and "whenNotPaused" in fn.modifiers:
        hit("SOL-EMERGENCY-PAUSED", f"`{fn.name}` has `whenNotPaused`, so it is off exactly when it is needed",
            fn.line, is_line=True)

    # FG-109 rescue that can take the staked token
    if mutating and authorized and RESCUE_FN.match(fn.name):
        stake_vars = [v for v, meta in sv.items() if STAKE_TOKEN_VAR.search(v) and not re.match(r"u?int|bool|mapping", meta["type"])]
        for ptype, p in fn.params:
            if ptype != "address" or not p or not stake_vars:
                continue
            pe = re.escape(p)
            if re.search(rf"(?<![\w$]){pe}\s*\)?\s*\.\s*(safeTransfer|transfer)\s*\(", full) \
                    and not re.search(rf"(?<![\w.$]){pe}\s*(==|!=)|(==|!=)\s*{pe}\b", full) \
                    and not any(re.search(rf"(?<![\w.$]){re.escape(v)}\b", full) for v in stake_vars):
                hit("SOL-RESCUE-DRAINS-STAKE", f"`{fn.name}` sends any `{p}` out, including `{stake_vars[0]}`",
                    fn.line, is_line=True)
                break

    # FG-110 fee/rate setter with no bound and no timelock anywhere
    if mutating and authorized and FEE_SETTER.match(fn.name) and not TIMELOCK_WORDS.search(sf.clean):
        nums = [p for t, p in fn.params if t.startswith(("uint", "int")) and p]
        if nums and sf.writes(c, fn.body_start, fn.body_end) and not any(
                re.search(rf"(?<![\w.$]){re.escape(p)}\s*[<>]|[<>]=?\s*{re.escape(p)}\b", full) for p in nums):
            hit("SOL-NO-TIMELOCK", f"`{fn.name}` sets `{nums[0]}` immediately with no maximum and no delay",
                fn.line, is_line=True)

    # FG-111 execute before eta
    if mutating and EXECUTE_FN.match(fn.name):
        ctext = sf.clean[c.start:c.end]
        if ETA_WORDS.search(ctext) and QUEUE_WORDS.search(ctext) and not TIME_READ.search(full):
            hit("SOL-TIMELOCK-BYPASS", f"`{fn.name}` never compares the queued ETA with `block.timestamp`",
                fn.line, is_line=True)

    # FG-113 ERC-721 _mint to a caller-chosen address
    if mutating and _nft_contract(sf, c, "721") and not _nft_contract(sf, c, "20|1155"):
        addrs = {p for t, p in fn.params if t == "address" and p}
        for m in re.finditer(r"(?<![\w.$])_mint\s*\(\s*([A-Za-z_]\w*)\s*,", body):
            if m.group(1) in addrs:
                hit("SOL-NFT-UNSAFE-MINT", f"`_mint({m.group(1)}, ...)` skips the receiver check", b0 + m.start())
                break

    # FG-114 state written after a receiver hook
    if mutating and not any(REENTRANCY_GUARDS.match(m) or "nonReentrant" in m for m in fn.modifiers):
        hooks = [m.start() for m in SAFE_HOOK.finditer(body)]
        if _nft_contract(sf, c, "1155"):
            hooks += [m.start() for m in re.finditer(r"(?<![\w.$])_mint\s*\(", body)]
        if hooks:
            first = b0 + min(hooks)
            late = [(off, v) for off, v in sf.writes(c, fn.body_start, fn.body_end) if off > first]
            if late:
                hit("SOL-NFT-HOOK-REENTRANCY", f"`{late[0][1]}` is written after the receiver hook in `{fn.name}`", late[0][0])

    # FG-115 / FG-116 NFT leaves the contract
    out = NFT_OUT.search(body)
    if mutating and out and re.match(r"^(unstake|withdraw|claim|redeem|exit|unlock|leave)\w*$", fn.name, re.I) \
            and any(t.startswith("uint") for t, _ in fn.params):
        maps = [v for v, meta in sv.items() if meta["type"].replace(" ", "").startswith("mapping(uint")
                and "=>address" in meta["type"].replace(" ", "") and STAKER_MAP.search(v)]
        for v in maps:
            if not _write_re(v).search(full):
                hit("SOL-NFT-STAKE-RECORD-DRIFT", f"`{fn.name}` returns the token but leaves `{v}[id]` set", fn.line, is_line=True)
                break
        recipient = out.group(1)
        addrs = {p for t, p in fn.params if t == "address" and p}
        if (recipient == "msg.sender" or recipient in addrs) and not authorized \
                and not re.search(r"msg\.sender\s*(==|!=)|(==|!=)\s*msg\.sender|_isApprovedOrOwner|_checkAuthorized|_isAuthorized|"
                                  r"(?<![\w.$])_burn\s*\(|(?<![\w.$])_update\s*\([^;]*(msg\.sender|_msgSender)|"
                                  r"\[\s*(msg\.sender|_msgSender\(\s*\))\s*\]\s*-=", full):
            hit("SOL-NFT-UNSTAKE-ANY", f"`{fn.name}` sends any staked token to `{recipient}` without checking the staker",
                b0 + out.start())

    # FG-117 parallel arrays
    if fn.exposed:
        arrays = [p for t, p in fn.params if t.endswith("[]") and p]
        if len(arrays) >= 2 and _loops(body):
            used = [a for a in arrays if re.search(rf"(?<![\w.$]){re.escape(a)}\s*\[", body)]
            whole = (rf"(?<![\w.$]){re.escape(used[0])}\b(?!\s*[\[.])[^;]*(?<![\w.$]){re.escape(used[1])}\b(?!\s*[\[.])"
                     if len(used) >= 2 else "")
            if len(used) >= 2 and not re.search(r"\.length\s*(==|!=)\s*[\w.]+\.length", full) \
                    and not re.search(r"\w\s*\([^;]*" + whole, body):  # both arrays handed whole to a check or hash
                hit("SOL-ARRAY-LENGTH-MISMATCH", f"`{fn.name}` indexes `{used[0]}` and `{used[1]}` without comparing lengths",
                    fn.line, is_line=True)

    # FG-119 hand-written transfer keeps the approval
    if re.search(r"transfer", fn.name, re.I) and fn.state_changing:
        owner_maps = [v for v, meta in sv.items() if re.match(r"^_?owners?$|^ownerOf$|^_ownerOf$", v) and "mapping" in meta["type"]]
        appr_maps = [v for v, meta in sv.items() if re.search(r"approv", v, re.I) and "mapping" in meta["type"]
                     and "=>bool" not in meta["type"].replace(" ", "")[-12:]]
        for v in owner_maps:
            m = re.search(rf"(?<![\w.$]){re.escape(v)}\s*\[[^\]]+\]\s*=(?!=)", body)
            if m and appr_maps and not re.search(r"delete\s+\w*[Aa]pprov\w*|[Aa]pprov\w*\s*\[[^\]]*\]\s*=\s*address\s*\(\s*0\s*\)|"
                                                 r"_approve\s*\(\s*address\s*\(\s*0", full):
                hit("SOL-NFT-APPROVAL-STALE", f"`{fn.name}` moves `{v}[id]` but leaves `{appr_maps[0]}[id]`", b0 + m.start())
                break

    # FG-120 claim pays but never zeroes
    if mutating and CLAIM_FN.match(fn.name) and PAYOUT.search(full):
        for m in OWED_READ.finditer(full):
            var = m.group(1)
            if var in sv and not _write_re(var).search(full):
                hit("SOL-REWARD-CLAIM-NO-RESET", f"`{fn.name}` pays `{var}[...]` and never sets it to zero", fn.line, is_line=True)
                break

    # FG-121 reward rate overwritten mid-period
    m = RATE_SET.search(body)
    if m and fn.state_changing:
        periods = [v for v in sv if PERIOD_VAR.match(v)]
        before = body[:m.start()]
        if periods and not any(re.search(rf"(?<![\w.$]){re.escape(p)}\b", before) for p in periods) \
                and not re.search(r"leftover|remaining", before, re.I):
            hit("SOL-REWARD-PERIOD-OVERWRITE", f"`{fn.name}` sets `rewardRate` without adding what `{periods[0]}` still owes",
                b0 + m.start())

    # FG-122 deposit-for resets someone else's lock
    if mutating and not authorized:
        for t, u in fn.params:
            if t != "address" or not u:
                continue
            m = re.search(LOCK_MAP_WRITE.format(u=re.escape(u)), body)
            if m and not re.search(rf"\b{re.escape(u)}\s*(==|!=)\s*(msg\.sender|_msgSender\(\s*\))|(msg\.sender|_msgSender\(\s*\))\s*(==|!=)\s*{re.escape(u)}\b|"
                                   r"isApproved|operator", full):
                hit("SOL-LOCK-GRIEFING", f"`{fn.name}` lets any caller push `{m.group(1)}[{u}]` forward", b0 + m.start())
                break

    # FG-123 vesting without an end cap
    if VEST_FN.search(fn.name):
        m = ELAPSED.search(full)
        if m and PER_DURATION.search(full) and "*" in full and not TS_COMPARE.search(full):
            hit("SOL-VESTING-OVERRUN", f"`{fn.name}` scales by elapsed time with no cap at the end date",
                b0 + body.find("block") if "block" in body else fn.line, is_line="block" not in body)

    # FG-124 receiver hook credits any collection
    if RECEIVER_FN.match(fn.name) and sf.writes(c, fn.body_start, fn.body_end) and not SENDER_CHECKED.search(full) \
            and not any(not NON_AUTH_MODIFIERS.match(m) for m in fn.modifiers):
        hit("SOL-RECEIVER-ANY-TOKEN", f"`{fn.name}` records a deposit without checking which contract called it",
            fn.line, is_line=True)


def solidity_pack16_contract(sf: _SolFile, c: SolContract, add) -> None:
    if c.kind in ("interface", "library"):
        return
    hit = _sol16_hit(add, c.name)
    ctext = sf.clean[c.start:c.end]

    # FG-106 accumulator without a scale factor
    accs = [v for v in c.state_vars if REWARD_ACC.match(v)]
    for v in accs:
        for m in re.finditer(rf"(?<![\w.$]){re.escape(v)}\s*(\+=|=(?!=))([^;]*);", ctext):
            if "/" in m.group(2) and not SCALE.search(m.group(2)):
                hit("SOL-REWARD-PRECISION", f"`{v}` grows by a quotient with no 1e18 scale", c.start + m.start())
                return
    for fn in c.functions:
        if re.match(r"^rewardPerToken$", fn.name, re.I):
            for m in re.finditer(r"\breturn\b([^;]*);", sf.body(fn)):
                if "/" in m.group(1) and not SCALE.search(m.group(1)):
                    hit("SOL-REWARD-PRECISION", f"`{fn.name}` divides by the total with no 1e18 scale",
                        fn.body_start + m.start())
                    return

    # FG-112 short timelock delay
    if re.search(r"\beta\b|queue|schedule|timelock", ctext, re.I):
        for m in DELAY_CONST.finditer(ctext):
            secs = int(m.group(2)) * UNIT_SECS[m.group(3)]
            if secs < 86400:
                hit("SOL-TIMELOCK-SHORT-DELAY", f"`{m.group(1)}` is {secs} s", c.start + m.start())
                break

    # FG-118 supply counter that only goes up
    maps = [v for v, meta in c.state_vars.items() if SUPPLY_MAP.search(v) and meta["type"].replace(" ", "").startswith("mapping(uint")]
    for v in maps:
        wr = re.compile(rf"(?<![\w.$]){re.escape(v)}\s*\[[^\]]*\]\s*\+=")
        if not any(wr.search(sf.body(f)) and re.search(r"(?<![\w.$])_mint\w*\s*\(", sf.body(f)) for f in c.functions):
            continue
        for f in c.functions:
            fb = sf.body(f)
            if f.kind == "function" and re.search(r"(?<![\w.$])_burn\w*\s*\(", fb) and not _write_re(v).search(_with_locals(sf, c, f)):
                hit("SOL-SUPPLY-DRIFT", f"`{f.name}` burns without lowering `{v}`", f.line, is_line=True)
                return


_SIG_LAYER = {
    "SOL-READONLY-REENTRANCY": "L4", "SOL-TWAP-SHORT-WINDOW": "L4", "SOL-ORACLE-BAD-PRICE": "L1",
    "SOL-IMPL-NOT-DISABLED": "L2", "SOL-UUPS-NO-AUTH": "L2", "SOL-PROXY-STORAGE-COLLISION": "L4",
    "SOL-STORAGE-GAP": "L4", "SOL-ARBITRARY-CALL": "L5", "SOL-SIG-MALLEABLE": "L2", "SOL-TIMESTAMP-EQUALITY": "L4",
    "SOL-GAS-STIPEND": "L5", "SOL-SHORT-CALLDATA": "L1", "SOL-DIRTY-ORDER": "L4", "SOL-SLIPPAGE-ZERO": "L1",
    "SOL-DEADLINE-NOW": "L1", "SOL-VOTE-DOUBLE-COUNT": "L4", "SOL-DELEGATE-INFLATION": "L4", "SOL-ETH-PUSH-LOOP": "L5",
    "SOL-MSG-VALUE-LOOP": "L4", "SOL-UNSAFE-DOWNCAST": "L4",
    # 0.16
    "SOL-STAKE-NO-LOCK": "L4", "SOL-REWARD-NOT-UPDATED": "L4", "SOL-REWARD-PRECISION": "L4",
    "SOL-REWARD-LOOP-DISTRIBUTION": "L5", "SOL-EMERGENCY-WITHDRAW-FLAW": "L4", "SOL-RESCUE-DRAINS-STAKE": "L2",
    "SOL-NO-TIMELOCK": "L2", "SOL-TIMELOCK-BYPASS": "L2", "SOL-TIMELOCK-SHORT-DELAY": "L9", "SOL-NFT-UNSAFE-MINT": "L5",
    "SOL-NFT-HOOK-REENTRANCY": "L5", "SOL-NFT-STAKE-RECORD-DRIFT": "L4", "SOL-NFT-UNSTAKE-ANY": "L2",
    "SOL-ARRAY-LENGTH-MISMATCH": "L1", "SOL-SUPPLY-DRIFT": "L4", "SOL-NFT-APPROVAL-STALE": "L2",
    "SOL-REWARD-CLAIM-NO-RESET": "L4", "SOL-REWARD-PERIOD-OVERWRITE": "L4", "SOL-LOCK-GRIEFING": "L2",
    "SOL-VESTING-OVERRUN": "L4", "SOL-RECEIVER-ANY-TOKEN": "L2", "SOL-EMERGENCY-PAUSED": "L9",
}


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

    inherited = _inherited_names(sf)
    nft_only = bool(re.search(r"\bI?ERC(721|1155)\w*", sf.clean)) and not re.search(r"\bI?ERC20\w*|SafeERC20", sf.clean)
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
                    add("SOL-ZERO-ADDRESS", "HIGH", "L1",
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

            # FG-06 ERC-20 return value ignored (ERC-721 transferFrom returns nothing, so NFT-only files are skipped)
            for m in ([] if nft_only else ERC20_CALL.finditer(body)):
                recv = " ".join(m.group(1).split())
                if recv in ("super", "this") or recv.startswith(("payable(", "payable (")):
                    continue
                args_end = match_close(body, m.end() - 1, "(", ")")
                argc = len(_split_params(body[m.end():args_end])) if args_end > m.end() else 0
                if argc < 2:
                    continue  # payable(x).transfer(amount) is the native transfer
                stmt_start = max(body.rfind(";", 0, m.start()), body.rfind("{", 0, m.start()), body.rfind("}", 0, m.start()))
                stmt = body[stmt_start + 1:m.start()]
                if not re.search(r"=|\breturn\b|require\s*\(|\bif\s*\(|\bassert\s*\(|!\s*$|&&|\|\|", stmt):
                    add("SOL-ERC20-UNCHECKED", "HIGH", "L5", f"Return value of `{recv}.{m.group(2)}` is ignored",
                        b0 + m.start(), "Use `SafeERC20` (`safeTransfer`, `safeTransferFrom`, `forceApprove`).",
                        contract=cname)

            # FG-07 transferFrom out of a caller-chosen address
            if fn.exposed and fn.kind == "function" and fn.state_changing and not _authorized(sf, c, fn):
                addr_params = {p[1] for p in fn.params if p[0] == "address" and p[1]}
                for m in TRANSFER_FROM.finditer(body):
                    src = m.group(2)
                    if src not in addr_params or re.search(r"(?<![\w.$])super\s*$", body[:m.start()]):
                        continue
                    if re.search(rf"\b{re.escape(src)}\s*(==|!=)\s*(msg\.sender|_msgSender\(\))|"
                                 rf"(msg\.sender|_msgSender\(\))\s*(==|!=)\s*{re.escape(src)}\b|allowance\s*\(|"
                                 rf"permit\s*\(|isApprovedForAll\s*\(|ecrecover|ECDSA|SignatureChecker", body):
                        continue
                    add("SOL-ARBITRARY-FROM", "CRITICAL", "L2",
                        f"`{fn.name}` pulls tokens from `{src}`, which the caller chooses", b0 + m.start(),
                        "Pull from `msg.sender` only; anyone can drain wallets that approved this contract.",
                        contract=cname)
                    break

            # FG-08 loop over a storage array in a state-changing entry point
            if fn.exposed and fn.state_changing:
                for m in STORAGE_LOOP.finditer(body):
                    arr = m.group(1)
                    if arr in c.state_vars and c.state_vars[arr]["type"].endswith("[]") and c.state_vars[arr]["mutable"]:
                        add("SOL-UNBOUNDED-LOOP", "HIGH", "L4",
                            f"`{fn.name}` loops over the whole `{arr}` storage array", b0 + m.start(),
                            "Paginate (start/count) or keep a running total; an unbounded loop can exceed the block gas limit.",
                            contract=cname)
                        break

            auth = _authorized(sf, c, fn)
            solidity_pack_fn(sf, c, fn, add, auth)
            solidity_pack16_fn(sf, c, fn, add, auth)

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
                add("SOL-WEAK-RANDOMNESS", "HIGH", "L4", f"Randomness from `{(m.group(1) or m.group(2)).split('(')[0]}`", b0 + m.start(),
                    "Use Chainlink VRF or commit-reveal; block values are known to (and set by) the block builder.",
                    contract=cname)
            m = DIV_BEFORE_MUL.search(body)
            if m:
                add("SOL-DIV-BEFORE-MUL", "HIGH", "L4", "Division before multiplication truncates", b0 + m.start(),
                    "Multiply first, or use `Math.mulDiv(a, b, c)` for full precision.", contract=cname)
            for m in re.finditer(r"\bunchecked\s*\{", body):
                inner = body[m.end():match_close(body, m.end() - 1)]
                if re.search(r"[\w)\]]\s*[-*]\s*[\w(]", inner):
                    add("SOL-UNCHECKED-MATH", "LOW", "L4", "Subtraction/multiplication inside `unchecked`",
                        b0 + m.start(), "Keep `unchecked` to loop counters and proven bounds; document the bound "
                        "next to each unchecked operation.", contract=cname)

        solidity_pack_contract(sf, c, add, inherited)
        solidity_pack16_contract(sf, c, add)

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

    solidity_pack_file(sf, add)
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
    LineRule("WEB-NOSQL", "HIGH", "L6", "NoSQL query built from the raw request object",
             _r(r"\$where\b|\.(find|findOne|findOneAndDelete|deleteOne|deleteMany|countDocuments|where|aggregate)\s*\(\s*"
                r"(req\.(body|query)|request\.(json|args|get_json\(\)))\s*\)"),
             "Pick the expected fields and cast them (`String(req.body.email)`); never pass `$where` or a whole body.",
             frozenset({PY, JS, PHP})),
    LineRule("WEB-SSTI", "CRITICAL", "L6", "Template built from request data",
             _r(r"(render_template_string|from_string|renderString|\bTemplate|ejs\.render|pug\.render|pug\.compile|"
                r"[Hh]andlebars\.compile|_\.template)\s*\([^)\n]*(request\.(args|form|values|json|get_json|data)|"
                r"req\.(body|query|params))|render_template_string\s*\(\s*(f['\"]|[^)\n]*(%\s*\(|\.format\(|\+\s*\w))"),
             "Render fixed template files and pass request values as context variables.", frozenset({PY, JS, PHP})),
    LineRule("WEB-SSRF", "HIGH", "L6", "Outbound request to a URL from the request",
             _r(r"(requests\.\w+|httpx\.\w+|urlopen|\bfetch|axios(?:\.\w+)?|\bgot(?:\.\w+)?|https?\.(?:get|request)|"
                r"curl_init)\s*\(\s*[^)\n]*(request\.(args|form|values|json|get_json)|req\.(body|query|params)|"
                r"\$_(GET|POST|REQUEST))"),
             "Allowlist hosts, block private and metadata addresses (169.254.169.254), and disable redirects.",
             frozenset({PY, JS, PHP})),
    LineRule("WEB-XXE", "HIGH", "L6", "XML parser resolves external entities",
             _r(r"resolve_entities\s*=\s*True|\bnoent\s*:\s*true|LIBXML_NOENT|libxml_disable_entity_loader\s*\(\s*false"),
             "Use defusedxml or switch entity resolution off.", frozenset({PY, JS, PHP})),
    LineRule("WEB-MASS-ASSIGNMENT", "HIGH", "L1", "Whole request body written into a model",
             _r(r"\.(create|update|insert|insertOne|insertMany|build|updateOne|updateMany|findOneAndUpdate|"
                r"findByIdAndUpdate|upsert)\s*\(\s*(?:[^,()]+(?:\([^()]*\))?\s*,\s*)?req\.body\s*[,)]|"
                r"new\s+[A-Z]\w*\s*\(\s*req\.body\s*\)|Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)|\{\s*\.\.\.req\.body\b|"
                r"[A-Z]\w*\s*\(\s*\*\*\s*request\.(json|form|get_json\(\)|values)|\.update\s*\(\s*\*\*\s*request\.|"
                r"for\s+\w+\s*,\s*\w+\s+in\s+request\.(json|form|get_json\(\))\.items\s*\(\s*\)|"
                r"(::create|->fill|->update)\s*\(\s*\$request->all\s*\(\s*\)"),
             "Copy only the fields the caller may change into the model.", frozenset({PY, JS, PHP})),
    LineRule("WEB-TIMING-COMPARE", "MEDIUM", "L7", "Secret compared with == (not constant time)",
             _r(r"\b[\w.$]*(?:token|secret|signature|hmac|digest|api_?key|apikey|otp|csrf)[\w$]*(?:\[[^\]]*\])?\s*"
                r"(?:===?|!==?)\s*(?!(?:null|undefined|None|True|False|true|false|0)\b|['\"`]|typeof\b)[A-Za-z_$(]", re.I),
             "Compare with `hmac.compare_digest` / `crypto.timingSafeEqual` / `hash_equals`.", frozenset({PY, JS, PHP}),
             unless=_r(r"compare_digest|timingSafeEqual|hash_equals|secure_compare|constantTimeEq|safeCompare")),
    LineRule("WEB-TOKEN-ENTROPY", "MEDIUM", "L7", "Token with too little entropy",
             _r(r"secrets\.token_(hex|bytes|urlsafe)\s*\(\s*([1-9]|1[0-5])\s*\)|randomBytes\s*\(\s*([1-9]|1[0-5])\s*\)|"
                r"random_bytes\s*\(\s*([1-9]|1[0-5])\s*\)|\buuid\.?uuid1\s*\(|"
                r"\buuidv1\s*\(|\buuid\.v1\s*\(|\buniqid\s*\(|Date\.now\(\)\.toString\(\s*36\s*\)|str\(\s*time\.time\(\)\s*\)"),
             "Use 16+ random bytes from a CSPRNG (`secrets.token_urlsafe(32)`).", WEB, needs=SECRET_TERMS),
    LineRule("WEB-COOKIE-INSECURE", "MEDIUM", "L7", "Session cookie flags switched off",
             _r(r"SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|httpOnly\s*:\s*false|\bsecure\s*:\s*false|"
                r"session\.cookie_(secure|httponly)['\"]?\s*,\s*['\"]?(0|false|off)", re.I),
             "Set `Secure; HttpOnly; SameSite=Lax` on session cookies.", frozenset({PY, JS, PHP}),
             needs=_r(r"cookie|session", re.I)),
    LineRule("WEB-MUTABLE-DEFAULT", "MEDIUM", "L4", "Mutable default argument shared between calls",
             _r(r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))"),
             "Default to `None` and create the list/dict inside the function.", frozenset({PY})),
    # ---------------------------------------------------------------- 0.16: FG-126..FG-150 (line rules)
    LineRule("WEB-IDOR-MUTATION", "HIGH", "L2", "Record changed or deleted by a URL id with no ownership check",
             _r(r"(findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove)\s*\(\s*req\.params\.\w+|"
                r"(deleteOne|deleteMany|updateOne|updateMany|findOneAndUpdate|findOneAndDelete|findOneAndRemove)\s*\(\s*"
                r"\{\s*_?id\s*:\s*req\.params\.\w+\s*\}|\.destroy\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*req\.params\.\w+\s*\}\s*\}|"
                r"filter_by\s*\(\s*id\s*=\s*\w*id\s*\)\s*\.\s*(delete|update)\s*\(|"
                r"objects\.filter\s*\(\s*(pk|id)\s*=\s*\w*(id|pk)\s*\)\s*\.\s*(delete|update)\s*\(|"
                r"session\.delete\s*\(\s*\w+\.query\.get(_or_404)?\s*\(\s*\w*id\s*\)\s*\)|"
                r"(DELETE\s+FROM|UPDATE)\s+\w+[^'\"]*WHERE\s+id\s*=\s*['\"]?\s*\.\s*\$_(GET|POST|REQUEST)", re.I),
             "Scope the write to the caller (`{ _id: id, owner: req.user.id }`) or check ownership first.",
             frozenset({PY, JS, PHP}), unless=signatures.OWNERSHIP),
    LineRule("WEB-WS-NO-ORIGIN", "HIGH", "L2", "WebSocket server without an Origin check",
             _r(r"new\s+(WebSocket\.Server|WebSocketServer|WS\.Server)\s*\(|websockets\.serve\s*\(|\bSock\s*\(\s*app\s*\)|"
                r"\bSocketIO\s*\(\s*app\b"),
             "Check the handshake Origin against an allowlist (`verifyClient`, `allowRequest`, `origins=`).",
             frozenset({PY, JS}), unless=_r(r"verifyClient|allowRequest|handleProtocols|cors_allowed_origins|"
                                            r"allowed_origins|origins\s*=|checkOrigin|\borigin\b", re.I)),
    LineRule("WEB-WS-NO-AUTH", "HIGH", "L2", "WebSocket connection accepted without authentication",
             _r(r"\.on\s*\(\s*['\"]connection['\"]|@\s*sock\.route\s*\(|@\s*socketio\.on\s*\(\s*['\"]connect['\"]|"
                r"websockets\.serve\s*\("),
             "Authenticate in the handshake (session cookie or short-lived token) and close the socket otherwise.",
             frozenset({PY, JS}), needs=_r(r"WebSocket|socket\.io|\bws\b|websockets|flask_sock|socketio", re.I),
             unless=_r(r"auth|jwt|passport|session|token|verify|cookie|login_required|current_user|req\.user", re.I)),
    LineRule("WEB-WS-UNBOUNDED-MESSAGE", "MEDIUM", "L9", "WebSocket server with no message size limit",
             _r(r"new\s+(WebSocket\.Server|WebSocketServer|WS\.Server)\s*\(|max_size\s*=\s*None|"
                r"maxHttpBufferSize\s*:\s*(\d{9,}|Infinity)"),
             "Set `maxPayload` / `maxHttpBufferSize` / `max_size` to what the protocol needs.",
             frozenset({PY, JS}), unless=_r(r"maxPayload")),
    LineRule("WEB-HEADER-INJECTION", "HIGH", "L6", "Response header value taken from the request",
             _r(r"\.(setHeader|set|header|append|writeHead)\s*\(\s*['\"`](?!Access-Control-Allow-Origin)[^'\"`]+['\"`]\s*,"
                r"[^)\n]*req\.(query|body|params|headers|cookies)|"
                r"headers\s*\[\s*['\"](?!Access-Control-Allow-Origin)[^'\"]+['\"]\s*\]\s*=\s*[^\n]*"
                r"request\.(args|form|values|headers|json|cookies|get_json)|"
                r"header\s*\(\s*['\"](?!Location)[^'\":]*:\s*['\"]?\s*\.\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)"),
             "Map request values to known header values, or strip CR/LF and validate before setting a header.",
             frozenset({PY, JS, PHP})),
    LineRule("WEB-LOG-INJECTION", "LOW", "L6", "Raw request value written to the log",
             _r(r"(console\.(log|info|warn|error)|logger\.\w+|\blog\.(info|warn|warning|error|debug)|"
                r"logging\.(info|warning|error|debug|critical)|error_log)\s*\([^)\n]*"
                r"(req\.(body|query|params)|request\.(args|form|values|json|get_json|data)|\$_(GET|POST|REQUEST))"),
             "Log structured fields or strip CR/LF from request values before logging them.",
             frozenset({PY, JS, PHP}), unless=_r(r"replace\(\s*/\[?\\r\\n|sanitize\w*[Ll]og|escape\w*[Ll]og")),
    LineRule("WEB-CACHE-PUBLIC-AUTH", "HIGH", "L9", "Authenticated response marked publicly cacheable",
             _r(r"Cache-Control['\"]?\s*[,:=]\s*['\"][^'\"]*\bpublic\b|cache_control\s*\([^)\n]*public\s*=\s*True|"
                r"cache_control\.public\s*=\s*True", re.I),
             "Send `Cache-Control: private, no-store` on responses built for a logged-in user.",
             frozenset({PY, JS, PHP}),
             needs=_r(r"req\.user|request\.user|current_user|g\.user|req\.session|session\[|Authorization|"
                      r"login_required|\$_SESSION|jwt", re.I)),
    LineRule("WEB-CACHE-KEY-NO-USER", "HIGH", "L9", "Per-user response cached under a key without the user",
             _r(r"\b\w*(cache|Cache|redis|memcached|lru|Lru)\w*\.(set|setex|put|setEx)\s*\(\s*req\.(originalUrl|url|path)\s*,|"
                r"@\s*cache\.cached\s*\((?![^)\n]*(key_prefix|make_cache_key|unless|query_string))|@\s*cache_page\s*\("),
             "Put the user id in the cache key or do not cache user-specific responses.",
             frozenset({PY, JS}),
             needs=_r(r"req\.user|request\.user|current_user|g\.user|req\.session|session\[", re.I)),
    LineRule("WEB-CACHE-POISON-HOST", "MEDIUM", "L9", "Response built from X-Forwarded-Host",
             _r(r"req\.(get|header)\s*\(\s*['\"]x-forwarded-host|req\.headers\s*\[\s*['\"]x-forwarded-host|"
                r"request\.headers(\.get\s*\(|\s*\[)\s*['\"]x-forwarded-host|HTTP_X_FORWARDED_HOST", re.I),
             "Build absolute URLs from a configured base URL.", frozenset({PY, JS, PHP})),
    LineRule("WEB-SAMESITE-NONE", "MEDIUM", "L7", "Session cookie with SameSite=None",
             _r(r"same_?site['\"]?\s*[:=]\s*['\"]none['\"]|SameSite=None", re.I),
             "Use `SameSite=Lax` (or Strict) for session cookies.", frozenset({PY, JS, PHP})),
    LineRule("WEB-SESSION-FIXATION", "HIGH", "L2", "User stored in the session without regenerating its id",
             _r(r"req\.session\.(user\w*|uid|account\w*|auth\w*|loggedIn|isAuthenticated)\s*=(?!=)|"
                r"\$_SESSION\s*\[\s*['\"](user\w*|uid|auth\w*|account\w*|logged\w*)['\"]\s*\]\s*=(?!=)"),
             "Regenerate the session id at login (`req.session.regenerate`, `session_regenerate_id(true)`).",
             frozenset({JS, PHP}), unless=_r(r"regenerate|session_regenerate_id|req\.logIn\s*\(|req\.login\s*\(")),
    LineRule("WEB-JWT-WEAK-SECRET", "HIGH", "L7", "JWT key is a short string literal",
             _r(r"\bjwt\.(sign|encode|verify|decode)\s*\([^,\n]+,\s*['\"][^'\"\n]{0,31}['\"]"),
             "Load a 256-bit random key from the secret store.", frozenset({PY, JS})),
    LineRule("WEB-PASSWORD-PLAINTEXT", "CRITICAL", "L7", "Password from the request stored without hashing",
             _r(r"\bpassword\w*['\"]?\s*[:=]\s*(req\.body(\.password\w*|\[['\"]password\w*['\"]\])|"
                r"request\.(form|json|values|args)(\[['\"]password\w*['\"]\]|\.get\(\s*['\"]password\w*['\"]\))|"
                r"request\.get_json\(\)\[['\"]password\w*['\"]\]|\$_POST\[['\"]password\w*['\"]\])", re.I),
             "Hash with argon2id or bcrypt before storing.", frozenset({PY, JS, PHP}),
             needs=_r(r"\.create\s*\(|\.insert\w*\s*\(|\.save\s*\(|INSERT\s+INTO|\.add\s*\(|new\s+[A-Z]\w*\s*\(|\bUser\s*\(", re.I),
             unless=_r(r"bcrypt|argon2|scrypt|pbkdf2|hash|passlib|werkzeug\.security|crypt\s*\(", re.I)),
    LineRule("WEB-HOST-HEADER-LINK", "HIGH", "L6", "Emailed link built from the Host header",
             _r(r"req\.(headers\.host|get\s*\(\s*['\"]host['\"]|hostname|header\s*\(\s*['\"]host['\"]|"
                r"headers\s*\[\s*['\"]host['\"]\s*\])|request\.(host\b|host_url|url_root|get_host\s*\(|"
                r"headers\.get\s*\(\s*['\"]host['\"])|\$_SERVER\s*\[\s*['\"]HTTP_HOST['\"]", re.I),
             "Build emailed links from a configured base URL.", frozenset({PY, JS, PHP}),
             needs=_r(r"reset|forgot|verify|confirm|invite|magic|activat", re.I)),
    LineRule("WEB-REGEX-INJECTION", "MEDIUM", "L6", "Regular expression built from request data",
             _r(r"new\s+RegExp\s*\(\s*[^)\n]*req\.(query|body|params)|"
                r"\bre\.(compile|search|match|fullmatch|findall|finditer|sub|split)\s*\(\s*[^,\n]*request\.(args|form|values|json|get_json)|"
                r"preg_\w+\s*\(\s*[^,\n]*\$_(GET|POST|REQUEST)|\$regex\s*:\s*req\.(query|body|params)"),
             "Escape the input (`re.escape`, `escapeRegExp`, `preg_quote`) or match literally.",
             frozenset({PY, JS, PHP}),
             unless=_r(r"escapeRegExp|escape-string-regexp|escapeStringRegexp|re\.escape|preg_quote|escaperegexp")),
    LineRule("WEB-PROTOTYPE-POLLUTION", "HIGH", "L6", "Request data deep-merged into an object",
             _r(r"(?:\b_\.|\blodash\.|\$\.|\bjQuery\.|(?<![\w.$]))(merge|mergeWith|defaultsDeep|setWith|deepmerge|deepMerge|"
                r"mergeDeep|extend)\s*\([^)\n]*req\.(body|query)|\b_\.set\s*\([^)\n]*req\.(body|query)"),
             "Validate against a schema first and merge into `Object.create(null)`; reject `__proto__` keys.",
             frozenset({JS})),
    LineRule("WEB-UPLOAD-FILENAME", "HIGH", "L1", "Upload saved under the client's filename",
             _r(r"\.save\s*\([^)\n]*\.filename\b|"
                r"(path\.(join|resolve)|writeFile\w*|createWriteStream|rename\w*|\.mv)\s*\([^)\n]*\.(originalname|originalFilename)\b|"
                r"\bcb\s*\(\s*null\s*,\s*file\.originalname|"
                r"move_uploaded_file\s*\([^,]+,\s*[^)\n]*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]"),
             "Generate the stored name yourself (uuid + allowed extension) or use `secure_filename`.",
             frozenset({PY, JS, PHP}),
             unless=_r(r"secure_filename|sanitize-filename|sanitizeFilename|randomUUID|uuid")),
    LineRule("WEB-GRAPHQL-INTROSPECTION", "LOW", "L9", "GraphQL introspection or GraphiQL on",
             _r(r"introspection\s*:\s*true|graphiql\s*[:=]\s*(true|True)"),
             "Disable introspection and the IDE outside development.", frozenset({PY, JS})),
    LineRule("WEB-GRAPHQL-NO-LIMIT", "MEDIUM", "L9", "GraphQL server with no depth or cost limit",
             _r(r"new\s+ApolloServer\s*\(|graphqlHTTP\s*\(|createYoga\s*\(|GraphQLView\.as_view\s*\(|GraphQLRouter\s*\("),
             "Add depth and complexity limits as validation rules.", frozenset({PY, JS}),
             unless=_r(r"depthLimit|depth_limit|depth-limit|QueryDepthLimiter|costAnalysis|queryComplexity|"
                       r"ComplexityLimit|maxDepth|max_depth|validationRules|validation_rules|MaxAliasesLimiter")),
    LineRule("WEB-API-STATE-NO-AUTH", "HIGH", "L2", "State-changing route with no authentication in the file",
             _r(r"\b(app|router|api|server|route|bp|blueprint)\s*\.\s*(post|put|patch|delete)\s*\(\s*['\"`]"
                r"(?![^'\"`]*(log-?in|sign-?(in|up)|register|auth|token|reset|forgot|webhook|health|otp))|"
                r"@\s*[\w.]+\.(post|put|patch|delete)\s*\(\s*['\"](?![^'\"]*(log-?in|sign-?(in|up)|register|auth|token|reset|"
                r"forgot|webhook|health|otp))|"
                r"@\s*[\w.]+\.route\s*\(\s*['\"](?![^'\"]*(log-?in|sign-?(in|up)|register|auth|token|reset|forgot|webhook|"
                r"health|otp))[^'\"]*['\"][^)\n]*methods\s*=\s*\[[^\]]*['\"](POST|PUT|PATCH|DELETE)['\"]", re.I),
             "Put POST/PUT/PATCH/DELETE routes behind the auth middleware or decorator.", frozenset({PY, JS}),
             unless=_r(r"auth|login_required|jwt|passport|session|token|requireUser|isAuthenticated|verify|current_user|"
                       r"req\.user|request\.user|permission|guard|protect|api_?key|signature|hmac", re.I)),
    LineRule("WEB-ERROR-LEAK", "MEDIUM", "L9", "Exception detail returned to the client",
             _r(r"res\.(status\s*\(\s*\d+\s*\)\s*\.)?(send|json|end|write)\s*\(\s*(\{[^}\n]*)?\b(err|error|e|ex|exception)\.(stack|message)\b|"
                r"res\.(status\s*\(\s*\d+\s*\)\s*\.)?(send|json)\s*\(\s*(err|error)\s*\)|"
                r"return\s+[^\n]*traceback\.format_exc\s*\(|"
                r"return\s+(jsonify\s*\([^)\n]*)?(str|repr)\s*\(\s*(e|err|exc|ex|error)\s*\)|"
                r"jsonify\s*\([^)\n]*(str|repr)\s*\(\s*(e|err|exc|ex|error)\s*\)|echo\s+\$e->getMessage"),
             "Log the error server-side and return a generic message with a request id.", frozenset({PY, JS, PHP})),
    LineRule("WEB-CORS-REFLECT", "HIGH", "L9", "CORS reflects the caller's Origin",
             _r(r"\borigin\s*:\s*true\b|origin\s*:\s*\(\s*\w+\s*,\s*(cb|callback|done)\s*\)\s*=>\s*(cb|callback|done)\s*\(\s*null\s*,\s*true\s*\)|"
                r"Access-Control-Allow-Origin['\"]\s*,\s*req\.(headers\.origin|headers\s*\[\s*['\"]origin['\"]\s*\]|"
                r"get\s*\(\s*['\"]origin['\"]\s*\)|header\s*\(\s*['\"]origin['\"]\s*\))|"
                r"\[\s*['\"]Access-Control-Allow-Origin['\"]\s*\]\s*=\s*request\.(headers|environ)|"
                r"Access-Control-Allow-Origin:\s*['\"]\s*\.\s*\$_SERVER\s*\[\s*['\"]HTTP_ORIGIN", re.I),
             "Compare the Origin to an allowlist before echoing it.", frozenset({PY, JS, PHP})),
    LineRule("WEB-WS-PLAINTEXT", "MEDIUM", "L8", "WebSocket over plain ws://",
             _r(r"['\"`]ws://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"),
             "Use wss:// for every non-local socket.", WEB),
)


def _lang(path: str) -> str | None:
    ext = Path(path).suffix.lower()
    return (PY if ext in PY_EXT else JS if ext in JS_EXT else HTML if ext in HTML_EXT else PHP if ext in PHP_EXT else None)


FILE_RULE_LAYER = {"WEB-BODY-LIMIT": "L9", "WEB-RATE-LIMIT": "L2", "WEB-SSRF": "L6", "WEB-IDOR": "L2",
                   "WEB-COOKIE-INSECURE": "L7", "WEB-XXE": "L6", "WEB-NO-HEADERS-MW": "L9", "WEB-VULN-DEPENDENCY": "L9",
                   "WEB-SESSION-COOKIE-CONFIG": "L7", "WEB-JWT-NO-EXPIRY": "L7"}


def check_manifest(rel: str, raw: str) -> list[Finding]:
    """FG-90: package.json, package-lock.json and requirements*.txt against the offline advisory list."""
    lines = raw.splitlines()
    sig = signatures.lookup("WEB-VULN-DEPENDENCY")
    return [Finding(rule, sig.severity, "L9", title, rel, ln, snippet(lines, ln), sig.mitigation)
            for rule, ln, title in signatures.check_manifest(rel, raw)]


def is_manifest(name: str) -> bool:
    low = name.lower()
    return low in ("package.json", "package-lock.json") or (low.startswith("requirements") and low.endswith(".txt"))


# Literal hints for the line rules: a rule runs line by line only when one of its hints occurs in the lowercased
# file. Each tuple is a superset of what the rule's pattern can match (every alternative of the pattern contains
# one of the hints), so skipping on a miss never changes the result; it only spares the regex engine a pass over
# every line of files that cannot match. Rules without an entry always run.
LINE_HINTS: dict[str, tuple[str, ...]] = {
    "WEB-EVAL": ("eval", "exec", "function", "settimeout"),
    "WEB-COMMAND": ("system", "popen", "shell", "child_process", "execsync", "passthru", "proc_open"),
    "WEB-SQL": ("execute", "query", "raw", "prepare"),
    "WEB-XSS": ("innerhtml", "outerhtml", "document.write", "dangerouslysetinnerhtml", "v-html", "safe", "markup",
                "insertadjacenthtml", "echo"),
    "WEB-INPUT-VALIDATION": ("request.", "req.", "$_", "urlsearchparams", "location."),
    "WEB-SECRET": ("key", "secret", "passwd", "password", "token", "akia", "sk-", "0x"),
    "WEB-TLS-OFF": ("verify", "rejectunauthorized", "node_tls_reject_unauthorized", "insecureskipverify"),
    "WEB-PLAIN-HTTP": ("http://",),
    "WEB-DESERIALIZE": ("pickle", "marshal", "yaml", "unserialize"),
    "WEB-DEBUG": ("debug", "display_errors"),
    "WEB-CORS-ANY": ("origin", "cors"),
    "WEB-TOKEN-STORAGE": ("localstorage",),
    "WEB-WEAK-RANDOM": ("random", "rand"),
    "WEB-WEAK-HASH": ("md5", "sha1"),
    "WEB-JWT-NONE": ("algorithms", "verify_signature", "jwt.decode", "ignoreexpiration"),
    "WEB-OPEN-REDIRECT": ("redirect", "location:"),
    "WEB-PATH-TRAVERSAL": ("request.", "req.", "$_"),
    "WEB-GLOBAL-STATE": ("global",),
    "WEB-NOSQL": ("$where", "req.", "request."),
    "WEB-SSTI": ("template", "from_string", "render", "compile"),
    "WEB-SSRF": ("request.", "req.", "$_"),
    "WEB-XXE": ("resolve_entities", "noent", "libxml"),
    "WEB-MASS-ASSIGNMENT": ("req.body", "request.", "$request->all"),
    "WEB-TIMING-COMPARE": ("token", "secret", "signature", "hmac", "digest", "api", "otp", "csrf"),
    "WEB-TOKEN-ENTROPY": ("token_", "randombytes", "random_bytes", "uuid", "uniqid", "date.now", "time.time"),
    "WEB-COOKIE-INSECURE": ("httponly", "secure"),
    "WEB-MUTABLE-DEFAULT": ("def",),
    "WEB-IDOR-MUTATION": ("delete", "update", "destroy", "remove"),
    "WEB-WS-NO-ORIGIN": ("websocket", "ws.server", "sock"),
    "WEB-WS-NO-AUTH": ("connection", "sock", "websockets"),
    "WEB-WS-UNBOUNDED-MESSAGE": ("websocket", "ws.server", "max_size", "maxhttpbuffersize"),
    "WEB-HEADER-INJECTION": ("set", "header", "append", "writehead"),
    "WEB-LOG-INJECTION": ("log",),
    "WEB-CACHE-PUBLIC-AUTH": ("cache-control", "cache_control"),
    "WEB-CACHE-KEY-NO-USER": ("cache", "redis", "memcached", "lru"),
    "WEB-CACHE-POISON-HOST": ("x-forwarded-host", "http_x_forwarded_host"),
    "WEB-SAMESITE-NONE": ("samesite", "same_site"),
    "WEB-SESSION-FIXATION": ("req.session.", "$_session"),
    "WEB-JWT-WEAK-SECRET": ("jwt.",),
    "WEB-PASSWORD-PLAINTEXT": ("password",),
    "WEB-HOST-HEADER-LINK": ("req.", "request.", "http_host"),
    "WEB-REGEX-INJECTION": ("regexp", "re.", "preg_", "$regex"),
    "WEB-PROTOTYPE-POLLUTION": ("merge", "defaultsdeep", "setwith", "extend", "_.set"),
    "WEB-UPLOAD-FILENAME": (".save", "originalname", "originalfilename", "move_uploaded_file"),
    "WEB-GRAPHQL-INTROSPECTION": ("introspection", "graphiql"),
    "WEB-GRAPHQL-NO-LIMIT": ("apolloserver", "graphqlhttp", "createyoga", "graphqlview", "graphqlrouter"),
    "WEB-API-STATE-NO-AUTH": ("post", "put", "patch", "delete"),
    "WEB-ERROR-LEAK": ("res.", "traceback", "str", "repr", "getmessage"),
    "WEB-CORS-REFLECT": ("origin",),
    "WEB-WS-PLAINTEXT": ("ws://",),
}
_PY_COMMENT = re.compile(r"(^|\s)#.*$")
LINE_MAX = 4000  # longer lines (minified bundles) are not matched line by line


def check_text(rel: str, raw: str, lang: str) -> list[Finding]:
    lines = raw.splitlines()
    # Strip comments for C-like and Python sources so commented-out code does not count.
    if lang == PY:
        clean_lines = [_PY_COMMENT.sub(r"\1", ln) for ln in lines]
    elif lang in (JS, PHP):
        clean_lines = strip_comments(raw, blank_strings=False, templates=True).splitlines()
    else:
        clean_lines = lines
    low = raw.lower()
    out: list[Finding] = []
    for rule in LINE_RULES:
        if lang not in rule.langs:
            continue
        if rule.needs and not rule.needs.search(raw):
            continue
        if rule.unless and rule.unless.search(raw):
            continue
        hints = LINE_HINTS.get(rule.rule)
        if hints and not any(h in low for h in hints):
            continue
        search = rule.pattern.search
        for i, ln in enumerate(clean_lines, 1):
            if len(ln) > LINE_MAX:
                continue
            if search(ln):
                out.append(Finding(rule.rule, rule.severity, rule.layer, rule.title, rel, i, snippet(lines, i),
                                   rule.mitigation))
    for rule, ln, title in signatures.check_backend(raw, lang) + signatures.missing_security_headers(raw, lang):
        sig = signatures.lookup(rule)
        out.append(Finding(rule, sig.severity, FILE_RULE_LAYER.get(rule, "L2"), title, rel, ln,
                           snippet(lines, ln), sig.mitigation))
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


@dataclass
class ScanConfig:
    """``[score]`` from foundryguard.toml."""
    ignore: tuple[str, ...] = ()  # glob patterns against the path relative to the scanned root
    max_depth: int | None = None  # directory levels walked below the root (0 = the root dir only)
    max_files: int = MAX_FILES
    severity: dict = field(default_factory=dict)  # rule -> severity or "off"
    source: str | None = None  # the toml file this came from

    @classmethod
    def from_dict(cls, cfg: dict, source: str | None = None) -> "ScanConfig":
        sc = cfg.get("score") or {}
        depth = sc.get("max_depth")
        return cls(tuple(str(x) for x in sc.get("ignore", ()) or ()), None if depth is None else max(int(depth), 0),
                   int(sc.get("max_files", MAX_FILES)), signatures.severity_overrides(cfg), source)

    def ignored(self, rel: str) -> bool:
        import fnmatch
        return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat.rstrip("/") + "/*")
                   or rel.startswith(pat.rstrip("/*") + "/") for pat in self.ignore)


def find_config(target: Path) -> Path | None:
    """The nearest foundryguard.toml at or above ``target`` (stops at a .git dir)."""
    d = target if target.is_dir() else target.parent
    for cand in (d, *d.parents):
        if (cand / CONFIG_FILE).is_file():
            return cand / CONFIG_FILE
        if (cand / ".git").exists():
            return None
    return None


def load_scan_config(target: Path, path: str | Path | None = None) -> ScanConfig:
    cfg_path = Path(path) if path else find_config(target)
    if not cfg_path:
        return ScanConfig()
    if not cfg_path.is_file():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    if __package__:
        from . import compiler
    else:
        import compiler  # type: ignore
    return ScanConfig.from_dict(compiler._toml(cfg_path), str(cfg_path))


_TEST_FILE = re.compile(r"(^test_|_test\.py$|\.test\.|\.spec\.)")
_SKIP_SUFFIXES = (".t.sol", ".s.sol", ".min.js", ".d.ts")


def discover(root: Path, config: ScanConfig | None = None) -> list[Path]:
    """Files to score under ``root``, in a stable order (a folder's own files, then its subfolders, sorted).

    Walks with ``os.scandir`` inside a context manager: one directory read per folder, entry types from the
    directory listing instead of a stat per file, and the handle closed before descending. Symlinked folders
    are listed but not entered, as with ``os.walk``.
    """
    if root.is_file():
        return [root]
    config = config or ScanConfig()
    files: list[Path] = []
    root_s = str(root)

    def rel_of(path: str) -> str:
        return Path(os.path.relpath(path, root_s)).as_posix()

    def walk(here: str, depth: int) -> bool:
        dirs: list[tuple[str, str, bool]] = []
        names: list[str] = []
        try:
            with os.scandir(here) as it:
                for entry in it:
                    try:
                        is_dir = entry.is_dir()
                    except OSError:
                        is_dir = False
                    if is_dir:
                        dirs.append((entry.name, entry.path, entry.is_symlink()))
                    else:
                        names.append(entry.name)
        except OSError:
            return True
        for f in sorted(names):
            path = os.path.join(here, f)
            if is_manifest(f):
                if not config.ignored(rel_of(path)):
                    files.append(Path(path))
                continue
            if Path(f).suffix.lower() not in SCANNED_EXT or f.endswith(_SKIP_SUFFIXES):
                continue
            if _TEST_FILE.search(f) or config.ignored(rel_of(path)):
                continue
            files.append(Path(path))
            if len(files) >= config.max_files:
                return False
        if config.max_depth is not None and depth >= config.max_depth:
            return True
        for name, path, link in sorted(dirs):
            if name in SKIP_DIRS or name.startswith(".") or config.ignored(rel_of(path)):
                continue
            if not link and not walk(path, depth + 1):
                return False
        return True

    walk(root_s, 0)
    return files


def read_source(p: Path, limit: int = MAX_FILE_BYTES) -> str | None:
    """One open and one bounded read per file (no separate stat). None when the file is larger than ``limit``.
    Newlines are normalised the way text mode would, so offsets and line numbers match ``read_text``."""
    with open(p, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        return None
    text = data.decode("utf-8", errors="replace")
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def iter_sources(files: Iterable[Path], notes: list[str], limit: int = MAX_FILE_BYTES) -> Iterator[tuple[Path, str]]:
    """Stream (path, text) one file at a time so only the file being scored is held in memory."""
    for p in files:
        try:
            raw = read_source(p, limit)
        except OSError as exc:
            notes.append(f"skipped {p.name}: {exc}")
            continue
        if raw is None:
            notes.append(f"skipped {p.name}: larger than {limit // 1000} KB")
            continue
        yield p, raw


def score_path(target: Path, presets: Iterable[int] = ALL_PRESETS, config: ScanConfig | None = None
               ) -> tuple[ScoreResult, dict[str, list[SolContract]]]:
    if __package__:
        from . import web_surface
    else:
        import web_surface  # type: ignore
    presets = frozenset(presets)
    target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"{target} does not exist")
    config = config if config is not None else load_scan_config(target)
    base = target.parent if target.is_file() else target
    files = discover(target, config)
    limiter_seen = headers_seen = False
    sol_sources: list[tuple[str, str]] = []
    findings: list[Finding] = []
    sol_contracts: dict[str, list[SolContract]] = {}
    lines = 0
    kinds = set()
    notes = []
    bridge_sources: list[tuple[str, str]] = []
    for p, raw in iter_sources(files, notes):
        rel = p.relative_to(base).as_posix() if p != base else p.name
        lines += raw.count("\n") + 1
        limiter_seen = limiter_seen or (p.suffix.lower() not in SOL_EXT and signatures.limiter_present(raw))
        headers_seen = headers_seen or (p.suffix.lower() not in SOL_EXT and signatures.headers_present(raw))
        if is_manifest(p.name):
            kinds.add("web")
            findings += check_manifest(rel, raw)
            continue
        if web_surface.relevant(rel, raw):
            bridge_sources.append((rel, raw))
        if p.suffix.lower() in SOL_EXT:
            sol_sources.append((rel, raw))
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
    bridge = None
    if bridge_sources:
        rep = web_surface.analyze(bridge_sources)
        if not rep.empty:
            findings += rep.findings
            bridge = rep.as_dict()
    if limiter_seen:  # a limiter wired up in another file (app-wide middleware) covers the auth routes
        findings = [f for f in findings if f.rule != "WEB-RATE-LIMIT"]
    if headers_seen:  # helmet/Talisman or explicit header code anywhere covers the app
        findings = [f for f in findings if f.rule != "WEB-NO-HEADERS-MW"]
    if sol_sources:
        findings += diamond_slots(sol_sources)
    findings = signatures.apply(findings, config.severity)
    if config.source:
        notes.append(f"config: {config.source}")
    kind = "mixed" if len(kinds) > 1 else (kinds.pop() if kinds else "empty")
    result = ScoreResult(str(target), kind, score(findings), findings, len(files), lines, sorted(presets), notes=notes,
                         bridge=bridge)
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
    findings = signatures.apply(findings)
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
             forge_timeout: float = 1800.0, opener=None, config_path: str | Path | None = None) -> tuple[ScoreResult, Path]:
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
        result, sol = score_path(path, presets, load_scan_config(path.expanduser().resolve(), config_path))
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
    (out / FINDINGS_LOG).write_text("\n".join(finding_digest(result)) + "\n", encoding="utf-8")
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
ol.plan pre.fix { margin: 4px 0 0; padding: 6px 8px; background: #f4f5f6; border-left: 3px solid #4a5560; font-size: 12px; }
span.sig { font-weight: 700; color: #2f3a44; }
details.sigdb { margin: 8px 0; } details.sigdb summary { cursor: pointer; font-weight: 700; padding: 4px 0; }
table.sigmatch { table-layout: fixed; width: 100%; min-width: 760px; } table.sigmatch td { vertical-align: top; word-break: break-word; }
table.sigmatch td.loc { white-space: normal; } table.sigmatch .ref { font-size: 11px; } table.sigmatch pre.fix { margin: 0; padding: 6px 8px; background: #f4f5f6;
  border-left: 3px solid #4a5560; font-size: 12px; white-space: pre-wrap; }
tr.sigrow td { color: #8a9096; } tr.sigrow td:nth-child(-n+5) { white-space: nowrap; } tr.sigrow.hit td { color: #111; } tr.sigrow.hit td.n { font-weight: 700; }
"""


def _h(v) -> str:
    return _html.escape(str(v), quote=True)


def _md(v) -> str:
    """Escaped text with `code` spans."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", _h(v))


def _pts(f: Finding) -> str:
    return f"-{f.points}" if f.points else "0 (cap)"


def _sig_tag(f: Finding) -> str:
    return f'<span class="sig">{_h(f.signature)}</span> ' if f.signature else ""


def _sig_rows(sigs, hits: dict[str, int], sev_now: dict[str, str]) -> list[str]:
    out = []
    for sig in sigs:
        n = hits[sig.id]
        sev = sev_now.get(sig.id, sig.severity)
        out.append(f'<tr class="sigrow{" hit" if n else ""}"><td>{_h(sig.id)}</td><td>{_h(sig.stack)}</td>'
                   f"<td>{_h(sig.rule)}</td><td><span class=\"sev {sev}\">{sev}</span></td><td>{_h(sig.ref)}</td>"
                   f'<td class="n">{n}</td><td>{_md(sig.title)}</td></tr>')
    return out


SIG_HEAD = ('<div class="scroll"><table><tr><th>ID</th><th>Stack</th><th>Rule</th><th>Severity</th><th>Ref</th>'
            '<th class="n">Hits</th><th>Signature</th></tr>')


def _id_ranges(sigs) -> str:
    """"FG-01 to FG-50 and FG-104 to FG-125" for the ids in ``sigs``."""
    nums = sorted(int(s.id[3:]) for s in sigs)
    runs: list[list[int]] = []
    for n in nums:
        if runs and n == runs[-1][1] + 1:
            runs[-1][1] = n
        else:
            runs.append([n, n])
    return " and ".join(f"FG-{a:02d} to FG-{b:02d}" for a, b in runs)


def signature_section(findings: list[Finding]) -> list[str]:
    """Layer 13: matched signatures with their fixes first, then the whole database split by surface."""
    hits = signatures.hits(findings)
    sev_now = {}
    for f in findings:
        if f.signature:
            sev_now.setdefault(f.signature, f.severity)
    matched = [s for s in signatures.SIGNATURES if hits[s.id]]
    web3 = [s for s in signatures.SIGNATURES if s.surface == "web3"]
    web2 = [s for s in signatures.SIGNATURES if s.surface == "web2"]
    out = ["<h2>Signature database</h2>",
           f'<p class="muted">{len(signatures.SIGNATURES)} signatures ({len(web3)} contract, {len(web2)} web), '
           f"{len(matched)} matched. Severities can be changed or switched off in foundryguard.toml under "
           "[score.severity].</p>"]
    if matched:
        out.append('<h3>Matched</h3><div class="scroll"><table class="sigmatch"><colgroup><col style="width:13%">'
                   '<col style="width:29%"><col style="width:6%"><col style="width:20%"><col style="width:32%">'
                   '</colgroup><tr><th>ID</th><th>Rule</th><th class="n">Hits</th><th>Where</th><th>Fix</th></tr>')
        for sig in matched:
            locs = [f.location for f in findings if f.signature == sig.id]
            where = "<br>".join(_h(x) for x in locs[:6]) + (f"<br>and {len(locs) - 6} more" if len(locs) > 6 else "")
            sev = sev_now.get(sig.id, sig.severity)
            out.append(f'<tr><td><span class="sig">{_h(sig.id)}</span><br><span class="sev {sev}">{sev}</span>'
                       f'<br><span class="muted ref">{_h(sig.ref)}</span></td>'
                       f"<td>{_h(sig.rule)}<br><span class=\"muted\">{_md(sig.title)}</span></td>"
                       f'<td class="n">{hits[sig.id]}</td><td class="loc">{where}</td>'
                       f'<td><pre class="fix">{_h(sig.fix)}</pre></td></tr>')
        out.append("</table></div>")
    for title, sigs in ((f"Contract surface, {_id_ranges(web3)}", web3), (f"Web surface, {_id_ranges(web2)}", web2)):
        n_hit = sum(1 for s in sigs if hits[s.id])
        out.append(f'<details class="sigdb"><summary>{_h(title)} ({n_hit} of {len(sigs)} matched)</summary>{SIG_HEAD}')
        out += _sig_rows(sigs, hits, sev_now)
        out.append("</table></div></details>")
    return out


def finding_digest(result: ScoreResult, limit: int | None = None) -> list[str]:
    """Plain-text report log: one block per deduction with severity, signature, file:line, points, the finding,
    the source line and the fix example. The desktop window prints it when a run ends; ``simulate`` writes it
    to foundryguard-findings.log next to the HTML report."""
    counts = result.counts()
    out = [f"FoundryGuard {result.score}/100 {result.verdict}: {result.target}",
           f"{len(result.findings)} deduction(s): " + ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES)
           + f"; {sum(1 for v in signatures.hits(result.findings).values() if v)} of {len(signatures.SIGNATURES)} "
             "signatures matched"]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ranked = sorted(result.findings, key=lambda f: (order.get(f.severity, 9), f.signature or "FG-999", f.file, f.line))
    shown = ranked if limit is None else ranked[:limit]
    for f in shown:
        tag = f.signature or "-"
        out.append("")
        out.append(f"[{f.severity}] {tag} {f.rule} {f.location} (-{f.points})")
        out.append(f"  {f.title.replace('`', '')}")
        if f.evidence:
            out.append(f"  > {f.evidence.strip()}")
        if f.fix:
            out.append("  fix:")
            out += [f"    {ln}" for ln in f.fix.splitlines()]
    if limit is not None and len(ranked) > limit:
        out.append("")
        out.append(f"... and {len(ranked) - limit} more in the report")
    return out


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
                       f"<td>{f.layer} {_h(LAYERS[f.layer])}</td>"
                       f"<td>{_sig_tag(f)}{_h(f.rule)}</td>"
                       f'<td class="loc">{_h(f.location)}</td><td class="n">{_pts(f)}</td>'
                       f'<td class="ev">{_md(f.title)}{ev}</td></tr>')
        out.append("</table></div>")

        out.append("<h2>Mitigation plan</h2><ol class=\"plan\">")
        by_rule: dict[str, list[Finding]] = {}
        for f in result.findings:
            by_rule.setdefault(f.rule, []).append(f)
        for rule, fs in by_rule.items():
            locs = ", ".join(f.location for f in fs[:12]) + (f" and {len(fs) - 12} more" if len(fs) > 12 else "")
            fix = f'<pre class="fix">{_h(fs[0].fix)}</pre>' if fs[0].fix else ""
            out.append(f'<li><span class="sev {fs[0].severity}">{fs[0].severity}</span> {_sig_tag(fs[0])}<b>{_h(rule)}</b>: '
                       f"{_md(fs[0].mitigation)}<br><span class=\"muted\">at {_h(locs)}</span>{fix}</li>")
        out.append("</ol>")

    out += signature_section(result.findings)

    if result.bridge:
        if __package__:
            from . import web_surface
        else:
            import web_surface  # type: ignore
        out += web_surface.html_section(result.bridge, _h)

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
    ap.add_argument("--config", help="foundryguard.toml to read [score] from (default: nearest one at or above the target)")


def cmd_score(args) -> int:
    try:
        presets = parse_presets(args.presets)
    except ValueError as exc:
        print(f"foundryguard: {exc}", file=sys.stderr)
        return 2
    try:
        result, page = simulate(args.target, presets, run_forge=args.fuzz, out_dir=args.out, ast_path=args.ast, config_path=args.config,
                                progress=lambda m: print("foundryguard: " + m, file=sys.stderr))
    except (FileNotFoundError, urllib.error.URLError, OSError, ValueError) as exc:
        print(f"foundryguard: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"{result.score}/100 {result.verdict}  {len(result.findings)} deduction(s)  {page}")
        for f in result.findings[:20]:
            print(f"  -{f.points:<3} {f.severity:<8} {f.layer:<3} {(f.signature or '-'):<6} {f.rule:<26} {f.location}  {f.title}")
        if len(result.findings) > 20:
            print(f"  ... {len(result.findings) - 20} more in the report")
        if result.bridge and result.bridge.get("links"):
            print(f"bridge map ({len(result.bridge['links'])} signing site(s)):")
            for ln in _bridge_lines(result.bridge):
                print(ln)
    return 1 if result.score < args.min_score else 0


def _bridge_lines(bridge: dict) -> list[str]:
    if __package__:
        from . import web_surface
    else:
        import web_surface  # type: ignore
    return web_surface.text_lines(bridge)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="foundryguard-score", description="Score a codebase or page from 1 to 100.")
    add_score_args(ap)
    return cmd_score(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
