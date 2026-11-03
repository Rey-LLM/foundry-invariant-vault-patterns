#!/usr/bin/env python3
"""FoundryGuard reporter: turn raw ``forge test`` output into ``FoundryGuard_Report.md``.

It reads either form forge prints:

* ``forge test --json`` (one JSON document, or one JSON object per line), including the
  ``counterexample.Sequence`` of a broken invariant and the shared-campaign ``failure`` events;
* plain ``forge test -vv`` / ``-vvv`` / ``-vvvv`` stdout, including the ``[Sequence]`` block
  under a ``[FAIL: ...]`` line, ``Logs:`` and ``Traces:`` sections. ANSI colours are stripped.

The report has a status badge per run, per suite and per test, a summary table, and for every
broken invariant or failed fuzz test the exact counter-example: the shrunk call sequence with
sender, target, function and arguments (argument names are read from the handler source when it
is on disk), a Solidity replay test, the ``forge`` command that reruns it, and the logs/traces forge
printed for it.

Usage::

    forge test --json > results.json;  python3 src/cli/reporter.py results.json
    forge test -vvv | tee forge.log;   python3 src/cli/reporter.py forge.log
    forge test -vvv | python3 src/cli/reporter.py -          # read stdin

    foundryguard report results.json    # same, plus the CI Markdown / SARIF outputs
    foundryguard run --test             # scan + gen + forge test + report

The report is written to ``<root>/FoundryGuard_Report.md`` unless ``-o`` says otherwise.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

if __package__:
    from . import reporting
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import reporting  # type: ignore

REPORT_FILE = "FoundryGuard_Report.md"
EVENTS_KEY = reporting.EVENTS_KEY

PASSED, FAILED, SKIPPED = "PASSED", "FAILED", "SKIPPED"
BADGE_COLOR = {PASSED: "brightgreen", FAILED: "red", SKIPPED: "lightgrey"}
ICON = {PASSED: "✅", FAILED: "❌", SKIPPED: "⏭️"}

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Call:
    sender: str | None
    target: str | None        # contract name, e.g. LeakyVaultGuardHandler
    target_path: str | None   # source path, e.g. test/foundryguard/LeakyVault/Handler.sol
    address: str | None
    function: str             # function name
    signature: str | None     # deposit(uint256,uint256)
    args: list[str] = field(default_factory=list)
    calldata: str | None = None


@dataclass
class TestResult:
    suite: str                # "<file>:<Contract>"
    name: str                 # "invariant_tokenSolvency()"
    status: str
    reason: str | None = None
    kind: str = "unit"        # unit | fuzz | invariant
    runs: int | None = None
    calls: int | None = None
    reverts: int | None = None
    gas: int | None = None
    sequence: list[Call] = field(default_factory=list)
    shrunk_from: int | None = None  # original sequence length before shrinking
    logs: list[str] = field(default_factory=list)
    traces: list[str] = field(default_factory=list)
    note: str | None = None

    @property
    def file(self) -> str:
        return self.suite.rpartition(":")[0]

    @property
    def contract(self) -> str:
        return self.suite.rpartition(":")[2]

    @property
    def func(self) -> str:
        return self.name.split("(")[0]


@dataclass
class Run:
    source: str
    fmt: str                  # "forge JSON" | "forge stdout"
    tests: list[TestResult] = field(default_factory=list)

    def suites(self) -> dict[str, list[TestResult]]:
        out: dict[str, list[TestResult]] = {}
        for t in self.tests:
            out.setdefault(t.suite, []).append(t)
        return out

    def count(self, status: str) -> int:
        return sum(1 for t in self.tests if t.status == status)

    @property
    def status(self) -> str:
        if self.count(FAILED):
            return FAILED
        return PASSED if self.tests else SKIPPED

    @property
    def failures(self) -> list[TestResult]:
        return [t for t in self.tests if t.status == FAILED]


# --------------------------------------------------------------------------- #
# forge --json
# --------------------------------------------------------------------------- #


def _status(raw) -> str:
    s = str(raw or "").lower()
    if s in ("success", "passed", "pass"):
        return PASSED
    if s in ("skipped", "skip"):
        return SKIPPED
    return FAILED


def _split_contract(name: str | None) -> tuple[str | None, str | None]:
    if not name:
        return None, None
    path, _, contract = name.rpartition(":")
    return contract or name, path or None


def _split_args(text: str | None) -> list[str]:
    """Split forge's printed argument list on top-level commas and drop `[1e18]` annotations."""
    if not text:
        return []
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    parts, depth, cur, quote = [], 0, [], None
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return [re.sub(r"\s+\[[-+0-9.eE]+\]$", "", p) for p in parts]


def _call_from_json(step: dict) -> Call:
    contract, path = _split_contract(step.get("contract_name"))
    sig = step.get("signature")
    func = step.get("func_name") or (sig.split("(")[0] if sig else None) or "?"
    args = step.get("args")
    return Call(sender=step.get("sender"), target=contract, target_path=path, address=step.get("addr"),
                function=func, signature=sig, args=_split_args(args) if isinstance(args, str) else list(args or []),
                calldata=step.get("calldata"))


def _kind_from_json(res: dict, t: TestResult) -> None:
    kind = res.get("kind")
    if isinstance(kind, dict) and kind:
        name, info = next(iter(kind.items()))
        info = info if isinstance(info, dict) else {}
        t.kind = name.lower()
        t.runs = info.get("runs")
        t.calls = info.get("calls")
        t.reverts = info.get("reverts")
        t.gas = info.get("gas") or info.get("median_gas") or info.get("mean_gas")
    elif t.name.startswith(("invariant", "statefulFuzz")):
        t.kind = "invariant"


def parse_json(data: dict, source: str = "forge JSON") -> Run:
    run = Run(source=source, fmt="forge JSON")
    for suite_id, suite in sorted(data.items()):
        if suite_id == EVENTS_KEY or not isinstance(suite, dict):
            continue
        results = suite.get("test_results") or {}
        for name, res in sorted(results.items()):
            if not isinstance(res, dict):
                continue
            t = TestResult(suite=suite_id, name=name, status=_status(res.get("status")), reason=res.get("reason"))
            _kind_from_json(res, t)
            counter = res.get("counterexample")
            if isinstance(counter, dict):
                if isinstance(counter.get("Sequence"), list):
                    t.sequence = [_call_from_json(s) for s in counter["Sequence"] if isinstance(s, dict)]
                    if t.kind == "unit":
                        t.kind = "invariant"
                elif isinstance(counter.get("Single"), dict):
                    t.sequence = [_call_from_json(counter["Single"])]
                    if t.kind == "unit":
                        t.kind = "fuzz"
            t.logs = [str(x) for x in res.get("decoded_logs") or []]
            run.tests.append(t)
    for ev in data.get(EVENTS_KEY, []):
        attribute(run, ev.get("target", ""), ev.get("invariant", "?"), ev.get("reason"))
    return run


def attribute(run: Run, suite_id: str, invariant: str, reason: str | None, how: str = "forge") -> TestResult:
    """Mark ``invariant`` of ``suite_id`` as the one that broke.

    Forge runs every invariant of a contract in one shared campaign. Its JSON files that campaign under
    the first invariant's name and reports the invariant that really broke in a separate
    ``{"event": "failure"}`` line (on stderr). The counter-example and campaign stats move to the real
    invariant; the stand-in entry becomes PASSED unless it broke too.
    """
    name = invariant if invariant.endswith(")") else f"{invariant}()"
    tests = [t for t in run.tests if t.suite == suite_id]
    hit = next((t for t in tests if t.name == name), None)
    if hit is None:
        hit = TestResult(suite=suite_id, name=name, status=FAILED, kind="invariant")
        run.tests.append(hit)
    campaign = next((t for t in tests if t is not hit and t.status == FAILED and not t.note and t.sequence), None) or \
        next((t for t in tests if t is not hit and t.status == FAILED and not t.note and t.kind == "invariant"), None)
    hit.status, hit.kind = FAILED, "invariant"
    hit.reason = reason or hit.reason
    if campaign is not None and (campaign.reason == hit.reason or not campaign.reason or how == "forge"):
        hit.sequence = hit.sequence or campaign.sequence
        hit.shrunk_from = hit.shrunk_from or campaign.shrunk_from
        for k in ("runs", "calls", "reverts"):
            if getattr(hit, k) is None:
                setattr(hit, k, getattr(campaign, k))
        hit.traces = hit.traces or campaign.traces
        campaign.status = PASSED
        campaign.note = (f"forge filed the shared invariant campaign under this name; the invariant that broke is `{name}`"
                         + (" (matched by its assertion message)" if how == "source" else ""))
    return hit


def resolve_from_source(run: Run, root: Path) -> None:
    """Without forge's failure events, find the broken invariant by its assertion message in the test source."""
    for t in list(run.failures):
        if t.kind != "invariant" or not t.reason or t.note:
            continue
        try:
            src = (root / t.file).read_text(encoding="utf-8")
        except OSError:
            continue
        for cand in (t.reason, t.reason.rsplit(": ", 1)[0]):
            idx = src.find(f'"{cand}"')
            if idx < 0:
                continue
            fns = list(re.finditer(r"\bfunction\s+(\w+)\s*\(", src[:idx]))
            if fns and fns[-1].group(1) != t.func and fns[-1].group(1).startswith(("invariant", "afterInvariant")):
                attribute(run, t.suite, fns[-1].group(1), t.reason, how="source")
            break


# --------------------------------------------------------------------------- #
# forge stdout
# --------------------------------------------------------------------------- #

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
RAN_RE = re.compile(r"^Ran \d+ tests? for (\S+)")
# The reason itself can contain brackets (`args=[1, 2]`), so it runs to the last `]` before the test name.
# Forge 1.x prints invariant names without parentheses (`[PASS] invariant_tokenSolvency`).
RESULT_RE = re.compile(r"^\[(PASS|FAIL|SKIP)(?:[:.]\s*(?:Reason:\s*)?(?P<reason>.*))?\]\s*(?P<rest>(?:[A-Za-z_$][\w$]*(?:\(.*)?)?)$")
TEST_LINE_RE = re.compile(r"^(?P<name>[A-Za-z_$][\w$]*(?:\([^)]*\))?)\s*(?P<stats>\(.*\))?\s*$")
BLOCK_HEAD_RE = re.compile(r"^(\S+) invariants:")                  # "XTest invariants: 1/3 invariants broken"
BLOCK_STATS_RE = re.compile(r"^(\S+) invariants (\(.*\))\s*$")     # "XTest invariants (runs: 32, calls: 1024, ...)"
SEQ_HEAD_RE = re.compile(r"^\[Sequence\](?:\s*\(original:\s*(\d+),\s*shrunk:\s*(\d+)\))?")
SEQ_STEP_RE = re.compile(
    r"sender=(?P<sender>0x[0-9a-fA-F]+)\s+addr=\[(?P<target>[^\]]+)\](?P<addr>0x[0-9a-fA-F]+)\s+"
    r"calldata=(?P<call>[^\s(]+(?:\([^)]*\))?)(?:\s+args=(?P<args>.*))?$"
)
COUNTER_RE = re.compile(r"counterexample:\s*calldata=(?P<calldata>0x[0-9a-fA-F]*)\s*args=(?P<args>\[.*\])", re.I)
STATS_RE = re.compile(r"(runs|calls|reverts|gas|μ|~):\s*(\d+)")


def _norm_name(name: str) -> str:
    return name if "(" in name else f"{name}()"


def _stats(text: str | None, t: TestResult) -> None:
    for key, val in STATS_RE.findall(text or ""):
        v = int(val)
        if key == "runs":
            t.runs = v
        elif key == "calls":
            t.calls = v
        elif key == "reverts":
            t.reverts = v
        elif key in ("gas", "~") or (key == "μ" and t.gas is None):
            t.gas = v
    if t.calls is not None or t.name.startswith(("invariant", "statefulFuzz", "afterInvariant")):
        t.kind = "invariant"
    elif t.runs is not None:
        t.kind = "fuzz"


def _call_from_text(m: re.Match) -> Call:
    contract, path = _split_contract(m.group("target"))
    call = m.group("call")
    sig = call if "(" in call else None
    return Call(sender=m.group("sender"), target=contract, target_path=path, address=m.group("addr"),
                function=call.split("(")[0], signature=sig, args=_split_args(m.group("args")))


def parse_stdout(text: str, source: str = "forge stdout") -> Run:
    run = Run(source=source, fmt="forge stdout")
    suite = "unknown:Unknown"
    pending: TestResult | None = None  # a [FAIL: ...] whose test name comes after its [Sequence]
    last: TestResult | None = None
    block: list[TestResult] | None = None  # forge 1.x "<Suite> invariants:" listing
    section: str | None = None           # "logs" | "traces" while inside one of those blocks
    seen: dict[tuple[str, str], TestResult] = {}
    events: list[dict] = []

    def finish(t: TestResult) -> TestResult:
        nonlocal last
        key = (t.suite, t.name)
        if key in seen:  # the "Failing tests:" recap and the 1.x campaign header repeat results
            t = seen[key]
        else:
            seen[key] = t
            run.tests.append(t)
        if block is not None and t not in block:
            block.append(t)
        last = t
        return t

    for raw in text.splitlines():
        line = ANSI.sub("", raw).rstrip()
        s = line.strip()
        if s.startswith("{") and '"event"' in s:
            try:
                ev = json.loads(s)
                if isinstance(ev, dict) and ev.get("event") == "failure" and "invariant" in ev:
                    events.append(ev)
                    continue
            except json.JSONDecodeError:
                pass
        m = RAN_RE.match(s)
        if m:
            suite, pending, last, block, section = m.group(1), None, None, None, None
            continue
        if s.startswith(("Suite result:", "Ran ", "Failing tests:", "Encountered ")):
            m2 = re.match(r"^Encountered \d+ failing tests? in (\S+)", s)
            if m2:
                suite = m2.group(1)
            section, block = None, None
            continue
        m = BLOCK_HEAD_RE.match(s)
        if m:
            if pending is not None and pending.name == "?":
                pending = None  # bare [PASS] / [FAIL] campaign header
            block, section = [], None
            continue
        m = BLOCK_STATS_RE.match(s)
        if m and block is not None:
            for t in block:
                _stats(m.group(2), t)
            last = next((t for t in block if t.status == FAILED), None)
            block, section = None, None
            continue
        m = RESULT_RE.match(s)
        if m:
            section = None
            status = {"PASS": PASSED, "FAIL": FAILED, "SKIP": SKIPPED}[m.group(1)]
            reason = (m.group("reason") or "").strip() or None
            t = TestResult(suite=suite, name="?", status=status, reason=reason)
            if reason:
                cm = COUNTER_RE.search(reason)
                if cm:
                    t.reason = reason[: cm.start()].rstrip("; ").strip() or None
                    t.sequence = [Call(sender=None, target=None, target_path=None, address=None, function="(fuzz input)",
                                       signature=None, args=_split_args(cm.group("args")), calldata=cm.group("calldata"))]
                    t.kind = "fuzz"
            tm = TEST_LINE_RE.match(m.group("rest") or "")
            if tm:
                t.name = _norm_name(tm.group("name"))
                _stats(tm.group("stats"), t)
                pending = None
                finish(t)
            else:
                pending, last = t, None
            continue
        if pending is not None:
            hm = SEQ_HEAD_RE.match(s)
            if hm:
                if hm.group(1):
                    pending.shrunk_from = int(hm.group(1))
                pending.kind = "invariant"
                continue
            sm = SEQ_STEP_RE.search(s)
            if sm:
                pending.sequence.append(_call_from_text(sm))
                continue
            tm = TEST_LINE_RE.match(s)
            if tm and tm.group("stats"):
                pending.name = _norm_name(tm.group("name"))
                _stats(tm.group("stats"), pending)
                finish(pending)
                pending = None
                continue
        if last is not None:
            if s == "Logs:":
                section = "logs"
                continue
            if s == "Traces:":
                section = "traces"
                continue
            if section and s:
                (last.logs if section == "logs" else last.traces).append(line.rstrip() if section == "traces" else s)
                continue
            if not s and section == "logs":
                section = None
    if pending is not None and pending.name != "?":
        finish(pending)
    for ev in events:
        attribute(run, ev.get("target", ""), ev.get("invariant", "?"), ev.get("reason"))
    return run


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def load(path: str) -> Run:
    """Load forge output from a file ('-' for stdin), detecting JSON or stdout."""
    if path == "-":
        text, source = sys.stdin.read(), "stdin"
    else:
        text, source = Path(path).read_text(encoding="utf-8", errors="replace"), path
    return parse_text(text, source)


def parse_text(text: str, source: str = "forge output") -> Run:
    data = try_json(text)
    if data and any(isinstance(v, dict) and "test_results" in v for v in data.values()):
        return parse_json(data, source)
    return parse_stdout(text, source)


def try_json(text: str) -> dict | None:
    """Merge every JSON object that starts a line: the forge --json document (one line or pretty-printed)
    plus ``{"event": "failure"}`` lines, ignoring compiler chatter mixed in through ``2>&1``."""
    text = ANSI.sub("", text)
    dec = json.JSONDecoder()
    merged: dict = {}
    pos = 0
    while pos < len(text):
        nl = text.find("\n", pos)
        line_end = len(text) if nl < 0 else nl
        start = pos + (len(text[pos:line_end]) - len(text[pos:line_end].lstrip()))
        if start < line_end and text[start] == "{":
            try:
                obj, end = dec.raw_decode(text, start)
            except json.JSONDecodeError:
                obj, end = None, line_end
            if isinstance(obj, dict):
                if obj.get("event") == "failure" and "invariant" in obj:
                    merged.setdefault(EVENTS_KEY, []).append(obj)
                elif obj.get("event") is None:
                    merged.update(obj)
            nl = text.find("\n", end)
            line_end = len(text) if nl < 0 else nl
        pos = line_end + 1
    return merged or None


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def badge(label: str, status: str, text: str | None = None) -> str:
    def esc(s: str) -> str:
        return s.replace("-", "--").replace("_", "__").replace(" ", "%20")
    msg = text or status
    color = BADGE_COLOR.get(status, "blue")
    left = f"{esc(label)}-" if label else ""
    alt = f"{label}: {msg}" if label else msg
    return f"![{alt}](https://img.shields.io/badge/{left}{esc(msg)}-{color}?style=flat-square)"


def _md(s: str | None) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _short(addr: str | None) -> str:
    if not addr:
        return "-"
    return f"{addr[:6]}…{addr[-4:]}" if len(addr) > 12 else addr


def _param_names(root: Path, call: Call, cache: dict) -> list[str]:
    """Parameter names of the called handler function, read from its source when available."""
    if not call.target_path or not call.signature:
        return []
    key = (call.target_path, call.signature)
    if key in cache:
        return cache[key]
    names: list[str] = []
    try:
        src = (root / call.target_path).read_text(encoding="utf-8")
        types = call.signature[call.signature.index("(") + 1:-1]
        for m in re.finditer(rf"\bfunction\s+{re.escape(call.function)}\s*\(([^)]*)\)", src):
            params = [p.split() for p in m.group(1).split(",") if p.strip()]
            if ",".join(p[0] for p in params) == types:
                names = [p[-1] if len(p) > 1 else "" for p in params]
                break
    except (OSError, ValueError):
        pass
    cache[key] = names
    return names


def _call_text(call: Call, names: list[str]) -> str:
    if names and len(names) == len(call.args):
        args = ", ".join(f"{n}: {a}" if n else a for n, a in zip(names, call.args))
    else:
        args = ", ".join(call.args)
    return f"{call.function}({args})"


def _sol_literal(a: str) -> str:
    a = a.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        return a
    if re.fullmatch(r"0x[0-9a-fA-F]*", a):
        return f'hex"{a[2:]}"'
    return a


def replay_snippet(t: TestResult) -> str | None:
    """A Solidity regression test that replays the shrunk sequence, then checks the invariant."""
    calls = [c for c in t.sequence if c.signature]
    if not calls:
        return None
    lines = [f"function test_replay_{t.func}() public {{"]
    for c in calls:
        recv = "handler" if (c.target or "").endswith("GuardHandler") else f"{c.target or 'Target'}(payable({c.address}))"
        if c.sender:
            lines.append(f"    vm.prank({c.sender});")
        lines.append(f"    {recv}.{c.function}({', '.join(_sol_literal(a) for a in c.args)});")
    if t.kind == "invariant":
        lines.append(f"    {t.func}();")
    lines.append("}")
    return "\n".join(lines)


def render(run: Run, root: Path | None = None, generated: str | None = None) -> str:
    root = root or Path(".")
    generated = generated or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    suites = run.suites()
    passed, failed, skipped = run.count(PASSED), run.count(FAILED), run.count(SKIPPED)
    out = [
        "# 🛡️ FoundryGuard Report",
        "",
        " ".join([badge("FoundryGuard", run.status), badge("passed", PASSED, str(passed)),
                  badge("failed", FAILED if failed else PASSED, str(failed)),
                  badge("skipped", SKIPPED, str(skipped))]),
        "",
        f"> Generated {generated} from `{run.source}` ({run.fmt}).",
        "",
    ]
    if not run.tests:
        out += ["⚠️ **No test results were found in the forge output.** Did the suites compile and run?", ""]
    elif failed:
        out += [f"**{ICON[FAILED]} {failed} of {len(run.tests)} test(s) failed.** "
                "The counter-examples below are the shrunk call sequences forge found.", ""]
    else:
        out += [f"**{ICON[PASSED]} All {passed} test(s) passed** across {len(suites)} suite(s).", ""]

    out += ["## Summary", "", "| Suite | Status | Passed | Failed | Skipped |", "| :-- | :-: | --: | --: | --: |"]
    for sid, tests in suites.items():
        st = FAILED if any(t.status == FAILED for t in tests) else PASSED
        out.append(f"| `{sid.rpartition(':')[2]}` | {badge('', st)} | {sum(t.status == PASSED for t in tests)} | "
                   f"{sum(t.status == FAILED for t in tests)} | {sum(t.status == SKIPPED for t in tests)} |")
    out += [f"| **Total** | {badge('', run.status)} | **{passed}** | **{failed}** | **{skipped}** |", ""]

    if run.failures:
        out += ["## Broken invariants and failed tests", ""]
        cache: dict = {}
        for t in run.failures:
            out += [f"### {ICON[FAILED]} `{t.contract}.{t.name}`", "", badge(t.kind, FAILED), ""]
            out.append(f"- **Suite:** `{t.suite}`")
            out.append(f"- **Reason:** `{_md(t.reason) or 'failed (no reason given)'}`")
            if t.kind == "invariant" and (t.runs is not None or t.calls is not None):
                out.append(f"- **Campaign:** {t.runs if t.runs is not None else '?'} run(s), "
                           f"{t.calls if t.calls is not None else '?'} call(s), {t.reverts if t.reverts is not None else '?'} revert(s)")
            if t.sequence and t.kind == "invariant":
                shrunk = f" (shrunk from {t.shrunk_from})" if t.shrunk_from and t.shrunk_from != len(t.sequence) else ""
                out.append(f"- **Counter-example:** {len(t.sequence)} call(s){shrunk}")
            if t.note:
                out.append(f"- **Note:** {t.note}")
            out.append("")
            if t.sequence:
                out += ["#### Counter-example call trace", "",
                        "| # | Sender | Target | Call |", "| --: | :-- | :-- | :-- |"]
                for i, c in enumerate(t.sequence, 1):
                    target = f"`{c.target}`" if c.target else "-"
                    if c.address:
                        target += f" `{_short(c.address)}`"
                    cell = f"`{_md(_call_text(c, _param_names(root, c, cache)))}`"
                    if c.calldata and not c.signature:
                        cell += f" (calldata `{c.calldata[:74]}{'…' if len(c.calldata) > 74 else ''}`)"
                    out.append(f"| {i} | `{_short(c.sender)}` | {target} | {cell} |")
                out.append("")
                out += ["```text"]
                for i, c in enumerate(t.sequence, 1):
                    who = f"{c.sender} -> " if c.sender else ""
                    tgt = f"{c.target}." if c.target else ""
                    out.append(f"{i:>2}. {who}{tgt}{c.function}({', '.join(c.args)})")
                if t.kind == "invariant":
                    out.append(f"    => {t.func}() broken: {t.reason or 'failed'}")
                out += ["```", ""]
                snippet = replay_snippet(t)
                if snippet:
                    out += ["<details><summary>Replay as a Foundry regression test</summary>", "",
                            f"Paste into `{t.contract}` (`{t.file}`) and run it with `-vvvv` to get the full trace.", "",
                            "```solidity", snippet, "```", "", "</details>", ""]
            else:
                out += ["_forge did not print a call sequence for this failure._", ""]
            out += ["Rerun just this test:", "", "```sh",
                    f"forge test --match-path '{t.file}' --match-contract '{t.contract}' --match-test '{t.func}' -vvvv",
                    "```", ""]
            if t.logs:
                out += ["<details><summary>Logs</summary>", "", "```text", *t.logs, "```", "", "</details>", ""]
            if t.traces:
                out += ["<details><summary>Traces</summary>", "", "```text", *t.traces, "```", "", "</details>", ""]

    out += ["## All tests", ""]
    for sid, tests in suites.items():
        st = FAILED if any(t.status == FAILED for t in tests) else PASSED
        out += [f"### `{sid.rpartition(':')[2]}` {badge('', st)}", "", f"`{sid}`", "",
                "| Status | Test | Kind | Runs | Calls | Reverts | Gas |", "| :-: | :-- | :-- | --: | --: | --: | --: |"]
        for t in tests:
            def n(v):
                return "-" if v is None else f"{v:,}"
            name = f"`{t.name}`" + (" ¹" if t.note else "")
            out.append(f"| {badge('', t.status)} | {name} | {t.kind} | {n(t.runs)} | {n(t.calls)} | {n(t.reverts)} | {n(t.gas)} |")
        notes = [t for t in tests if t.note]
        if notes:
            out += [""] + [f"¹ `{t.name}`: {t.note}." for t in notes]
        out.append("")
    out += ["---", "",
            "_Generated by [FoundryGuard](https://github.com/Rey-LLM/foundry-invariant-vault-patterns). "
            "A passing invariant held for every call sequence forge tried; it is evidence, not a proof._", ""]
    return "\n".join(out)


def load_persisted_sequences(run: Run, root: Path, cache_dir: str = "cache") -> None:
    """Fill missing counter-examples from forge's persisted failures.

    Forge 1.x prints no ``[Sequence]`` for a shared invariant campaign, but it stores the shrunk call
    sequence of every broken invariant in ``cache/invariant/failures/<TestContract>/<invariant>``.
    """
    for t in run.failures:
        if t.sequence or t.kind != "invariant":
            continue
        path = root / cache_dir / "invariant" / "failures" / t.contract / t.func
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        seq = data.get("call_sequence") if isinstance(data, dict) else data
        if isinstance(seq, list):
            t.sequence = [_call_from_json(step) for step in seq if isinstance(step, dict)]
            if t.sequence:
                t.note = (t.note + "; " if t.note else "") + f"counter-example read from `{path.relative_to(root).as_posix()}`"


def write_report(run: Run, root: Path, output: str | None = None) -> Path:
    resolve_from_source(run, root)
    load_persisted_sequences(run, root)
    path = Path(output) if output else root / REPORT_FILE
    if not path.is_absolute() and output:
        path = Path.cwd() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(run, root))
    return path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="foundryguard-report",
                                 description=f"Turn forge test output (JSON or stdout) into {REPORT_FILE}.")
    ap.add_argument("results", help="file with `forge test --json` or `forge test -vvv` output, or '-' for stdin")
    ap.add_argument("--root", default=".", help="project root: the report goes here and handler sources are read from here")
    ap.add_argument("-o", "--output", help=f"report path (default: <root>/{REPORT_FILE})")
    ap.add_argument("--fail-on-failure", action="store_true", help="exit 1 if a test failed or no results were found")
    args = ap.parse_args(argv)
    run = load(args.results)
    path = write_report(run, Path(args.root), args.output)
    print(f"foundryguard: {path} [{run.status}] {run.count(PASSED)} passed, {run.count(FAILED)} failed, "
          f"{run.count(SKIPPED)} skipped", file=sys.stderr)
    if args.fail_on_failure and (run.status != PASSED):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
