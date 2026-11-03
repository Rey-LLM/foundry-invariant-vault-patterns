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

The report is written to ``<root>/FoundryGuard_Report.md`` unless ``-o`` says otherwise, and the same
results go to ``foundryguard-report.html`` next to it: one static page (no scripts, no external files)
with run metrics, a collapsible call tree per failed execution path, and every test (``--html PATH`` to
move it, ``--no-html`` to skip it).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html as _html
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
    campaign: str | None = None     # set when forge ran this invariant in a campaign shared with others

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
    suite_time: dict[str, float] = field(default_factory=dict)  # seconds, from forge's per-suite duration
    wall_time: float | None = None    # seconds, forge's "Ran N test suites in X" (stdout only)

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


DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(ns|µs|μs|us|ms|s|m|h)(?![a-z])")
DURATION_UNIT = {"ns": 1e-9, "µs": 1e-6, "μs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}


def parse_duration(value) -> float | None:
    """Seconds from a forge duration: ``"412.10ms"``, ``"1m 2s"`` or serde's ``{"secs": 1, "nanos": 5}``."""
    if isinstance(value, dict) and ("secs" in value or "nanos" in value):
        return float(value.get("secs") or 0) + float(value.get("nanos") or 0) / 1e9
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str):
        return None
    parts = DURATION_RE.findall(value)
    if not parts:
        return None
    return sum(float(n) * DURATION_UNIT[u] for n, u in parts)


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
        secs = parse_duration(suite.get("duration"))
        if secs is not None:
            run.suite_time[suite_id] = secs
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
        if hit.calls == campaign.calls and hit.runs == campaign.runs:
            # one campaign, now listed under two names: count its calls once
            key = campaign.campaign or f"{campaign.suite}::{campaign.name}"
            campaign.campaign = hit.campaign = key
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
RAN_ALL_RE = re.compile(r"^Ran \d+ test suites? in (.+?)(?:\s*\(.*CPU time\))?:")
SUITE_TIME_RE = re.compile(r"finished in ([^()]+?)\s*(?:\(|$)")
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
        if s.startswith("Suite result:") and suite not in run.suite_time:
            tm2 = SUITE_TIME_RE.search(s)
            secs = parse_duration(tm2.group(1)) if tm2 else None
            if secs is not None:
                run.suite_time[suite] = secs
        m = RAN_ALL_RE.match(s)
        if m:
            run.wall_time = parse_duration(m.group(1))
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
                if len(block) > 1:
                    t.campaign = f"{suite}::invariants"
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
        "# FoundryGuard Report",
        "",
        " ".join([badge("FoundryGuard", run.status), badge("passed", PASSED, str(passed)),
                  badge("failed", FAILED if failed else PASSED, str(failed)),
                  badge("skipped", SKIPPED, str(skipped))]),
        "",
        f"> Generated {generated} from `{run.source}` ({run.fmt}).",
        "",
    ]
    if not run.tests:
        out += ["**No test results were found in the forge output.** Did the suites compile and run?", ""]
    elif failed:
        out += [f"**{failed} of {len(run.tests)} test(s) failed.** "
                "The counter-examples below are the shrunk call sequences forge found.", ""]
    else:
        out += [f"**All {passed} test(s) passed** across {len(suites)} suite(s).", ""]

    out += ["## Summary", "", "| Suite | Status | Passed | Failed | Skipped |", "| :-- | :-: | --: | --: | --: |"]
    for sid, tests in suites.items():
        st = FAILED if any(t.status == FAILED for t in tests) else PASSED
        out.append(f"| `{sid.rpartition(':')[2]}` | {badge('', st)} | {sum(t.status == PASSED for t in tests)} | "
                   f"{sum(t.status == FAILED for t in tests)} | {sum(t.status == SKIPPED for t in tests)} |")
    out += [f"| **Total** | {badge('', run.status)} | **{passed}** | **{failed}** | **{skipped}** |", ""]
    m = metrics(run)
    out += ["| Invariants checked | Fuzz inputs | Execution time |", "| --: | --: | --: |",
            f"| {m.invariants:,} | {m.fuzz_inputs:,} | {format_seconds(m.time)} |", ""]

    if run.failures:
        out += ["## Broken invariants and failed tests", ""]
        cache: dict = {}
        for t in run.failures:
            out += [f"### `{t.contract}.{t.name}`", "", badge(t.kind, FAILED), ""]
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


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def is_invariant(t: TestResult) -> bool:
    """An invariant property. ``afterInvariant`` is a hook forge calls after a campaign, not a property."""
    return t.kind == "invariant" and not t.func.startswith("afterInvariant")


@dataclass
class Metrics:
    tests: int
    passed: int
    failed: int
    skipped: int
    suites: int
    invariants: int            # invariant properties checked
    invariants_broken: int
    campaigns: int             # distinct invariant campaigns (forge 1.x runs a contract's invariants in one)
    invariant_runs: int
    invariant_calls: int
    fuzz_tests: int
    fuzz_runs: int
    wall_time: float | None    # forge's own wall clock for the whole run
    suite_time: float | None   # sum of per-suite durations (suites run in parallel, so this can exceed wall time)

    @property
    def fuzz_inputs(self) -> int:
        """Inputs the fuzzer generated: one per handler call in invariant campaigns, one per fuzz run."""
        return self.invariant_calls + self.fuzz_runs

    @property
    def time(self) -> float | None:
        return self.wall_time if self.wall_time is not None else self.suite_time


def metrics(run: Run) -> Metrics:
    """Totals for the report header.

    Each invariant campaign is counted once. Forge 1.x runs all invariants of a test contract in one
    campaign and prints its stats on every one of them, and ``attribute`` copies the campaign stats to
    the invariant that broke, so summing per test would count the same calls several times.
    """
    invariants = [t for t in run.tests if is_invariant(t)]
    seen: dict[str, tuple[int, int]] = {}
    for t in invariants:
        if t.runs is None and t.calls is None:
            continue
        key = t.campaign or f"{t.suite}::{t.name}"
        if key not in seen:
            seen[key] = (t.runs or 0, t.calls or 0)
    fuzz = [t for t in run.tests if t.kind == "fuzz"]
    return Metrics(
        tests=len(run.tests), passed=run.count(PASSED), failed=run.count(FAILED), skipped=run.count(SKIPPED),
        suites=len(run.suites()), invariants=len(invariants),
        invariants_broken=sum(t.status == FAILED for t in invariants), campaigns=len(seen),
        invariant_runs=sum(r for r, _ in seen.values()), invariant_calls=sum(c for _, c in seen.values()),
        fuzz_tests=len(fuzz), fuzz_runs=sum(t.runs or 0 for t in fuzz),
        wall_time=run.wall_time, suite_time=sum(run.suite_time.values()) if run.suite_time else None,
    )


def format_seconds(secs: float | None) -> str:
    if secs is None:
        return "-"
    if secs < 1e-3:
        return f"{secs * 1e6:.0f} µs"
    if secs < 1:
        return f"{secs * 1e3:.2f} ms"
    if secs < 60:
        return f"{secs:.2f} s"
    return f"{int(secs // 60)} min {secs % 60:.1f} s"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

HTML_FILE = "foundryguard-report.html"

HTML_CSS = """
:root { --ink: #222; --muted: #666; --line: #d0d0d0; --soft: #f4f4f4; --pass: #2e7d32; --fail: #c62828; --skip: #757575; }
* { box-sizing: border-box; }
html { background: #fafafa; }
body { margin: 0; padding: 32px 16px 48px; background: #fafafa; color: var(--ink);
       font: 13px/1.5 SFMono-Regular, Menlo, Consolas, "Liberation Mono", "Courier New", monospace; }
main { max-width: 1120px; margin: 0 auto; background: #fff; border: 1px solid var(--line); padding: 28px 32px; }
h1 { font-size: 18px; font-weight: 700; margin: 0 0 4px; letter-spacing: 0; }
h2 { font-size: 14px; font-weight: 700; margin: 32px 0 10px; padding-bottom: 4px; border-bottom: 1px solid var(--ink); text-transform: uppercase; }
h3 { font-size: 13px; font-weight: 700; margin: 20px 0 8px; }
p { margin: 6px 0; }
.sub { color: var(--muted); margin: 0 0 20px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; }
th, td { border: 1px solid var(--line); padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: var(--soft); font-weight: 700; }
td.n, th.n { text-align: right; white-space: nowrap; }
table.kv th { width: 200px; }
.badge { display: inline-block; padding: 0 6px; font-size: 11px; font-weight: 700; color: #fff; line-height: 18px; }
.PASSED { background: var(--pass); } .FAILED { background: var(--fail); } .SKIPPED { background: var(--skip); }
code, pre { font-family: inherit; }
pre { background: var(--soft); border: 1px solid var(--line); padding: 8px 10px; overflow-x: auto; margin: 6px 0 10px; white-space: pre; }
details { margin: 4px 0; }
summary { cursor: pointer; padding: 2px 0; }
details.failure { border: 1px solid var(--line); border-left: 3px solid var(--fail); padding: 6px 12px; margin: 12px 0; }
details.failure > summary { font-weight: 700; }
ol.tree { list-style: none; margin: 6px 0 10px; padding: 0 0 0 4px; border-left: 1px solid var(--line); }
ol.tree > li { margin: 0; padding: 2px 0 2px 12px; }
ol.tree table { width: auto; min-width: 60%; }
.idx { color: var(--muted); }
.fn { font-weight: 700; }
.muted { color: var(--muted); }
.up { color: var(--pass); } .down { color: var(--fail); }
.scroll { overflow-x: auto; }
footer { margin-top: 32px; padding-top: 8px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
@media (max-width: 640px) { main { padding: 16px; } table.kv th { width: auto; } }
@media print { html, body { background: #fff; } main { border: 0; } details { display: block; } }
"""

FRAME_RE = re.compile(r"^(?P<indent>[\s│├└─]*)\[\d+\]\s+(?P<contract>[\w$]+)::(?P<func>[\w$]+)\(")
STORAGE_RE = re.compile(r"@\s*(?P<slot>0x[0-9a-fA-F]+|\d+)\s*:\s*(?P<old>\S+)\s*(?:→|->)\s*(?P<new>\S+)")
CHECK_RE = re.compile(r"(?P<left>-?(?:0x[0-9a-fA-F]+|\d+))\s*(?P<op>!=|==|<=|>=|<|>)\s*(?P<right>-?(?:0x[0-9a-fA-F]+|\d+))\s*$")


@dataclass
class Frame:
    contract: str
    func: str
    storage: list[tuple[str, str, str]] = field(default_factory=list)  # (slot, old, new)


def trace_frames(lines: list[str]) -> list[Frame]:
    """Top-level call frames of a forge trace and the storage changes printed under each (-vvvvv)."""
    parsed = []
    for line in lines:
        m = FRAME_RE.match(line)
        if m:
            parsed.append((len(m.group("indent")), Frame(m.group("contract"), m.group("func"))))
        else:
            sm = STORAGE_RE.search(line)
            if sm:
                parsed.append((None, (sm.group("slot"), sm.group("old"), sm.group("new"))))
    depths = [d for d, _ in parsed if d is not None]
    if not depths:
        return []
    top = min(depths)
    frames: list[Frame] = []
    for depth, item in parsed:
        if depth is None:
            if frames:
                frames[-1].storage.append(item)
        elif depth == top:
            frames.append(item)
    return frames


def _int(v: str) -> int | None:
    try:
        return int(v, 0)
    except ValueError:
        return None


def _h(v) -> str:
    return _html.escape("" if v is None else str(v), quote=True)


def _badge_html(status: str) -> str:
    return f'<span class="badge {_h(status)}">{_h(status)}</span>'


def _num(v) -> str:
    return "-" if v is None else f"{v:,}"


def _kv(rows: list[tuple[str, str]]) -> str:
    """Two-column table; values are already HTML."""
    return '<table class="kv">' + "".join(f"<tr><th>{_h(k)}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"


def _storage_rows(storage: list[tuple[str, str, str]]) -> str:
    out = ['<table><tr><th>slot</th><th>before</th><th>after</th><th class="n">delta</th></tr>']
    for slot, old, new in storage:
        a, b = _int(old), _int(new)
        delta = "-" if a is None or b is None else (f'<span class="up">+{b - a:,}</span>' if b >= a
                                                   else f'<span class="down">{b - a:,}</span>')
        out.append(f"<tr><td>{_h(slot)}</td><td>{_h(old)}</td><td>{_h(new)}</td><td class=\"n\">{delta}</td></tr>")
    return "".join(out) + "</table>"


def _call_node(i: int, c: Call, names: list[str], frame: Frame | None) -> str:
    target = f"{c.target}." if c.target else ""
    head = (f'<span class="idx">{i:02d}</span>  {_h(target)}<span class="fn">{_h(c.function)}</span>'
            f"({_h(_call_text(c, names)[len(c.function) + 1:-1])})")
    rows = [("sender", _h(c.sender or "-")), ("target", _h(f"{c.target or '-'}" + (f" @ {c.address}" if c.address else ""))),
            ("signature", _h(c.signature or "-"))]
    types = c.signature[c.signature.index("(") + 1:-1].split(",") if c.signature and "(" in c.signature else []
    for k, a in enumerate(c.args):
        name = names[k] if k < len(names) and names[k] else f"arg{k}"
        ty = types[k] if k < len(types) and types[k] else ""
        rows.append((f"param {name}" + (f" ({ty})" if ty else ""), _h(a)))
    if c.calldata and c.calldata != "0x":
        rows.append(("calldata", f'<div class="scroll">{_h(c.calldata)}</div>'))
    body = _kv(rows)
    if frame and frame.storage:
        body += "<p>storage changes</p>" + _storage_rows(frame.storage)
    return f"<li><details><summary>{head}</summary>{body}</details></li>"


def _check_node(t: TestResult, n: int, frame: Frame | None) -> str:
    rows = [("result", _badge_html(FAILED)), ("reason", _h(t.reason or "failed (no reason given)"))]
    m = CHECK_RE.search(t.reason or "")
    if m:
        a, b = _int(m.group("left")), _int(m.group("right"))
        rows += [("left", _h(m.group("left"))), ("right", _h(m.group("right"))), ("expected", _h(f"left {m.group('op')} right is false"))]
        if a is not None and b is not None:
            rows.append(("drift (left - right)", _h(f"{a - b:+,}")))
    body = _kv(rows)
    if frame and frame.storage:
        body += "<p>storage changes</p>" + _storage_rows(frame.storage)
    return (f'<li><details open><summary><span class="idx">{n:02d}</span>  check '
            f'<span class="fn">{_h(t.func)}</span>()  {_badge_html(FAILED)}</summary>{body}</details></li>')


def _failure_html(t: TestResult, root: Path, cache: dict) -> str:
    reason = t.reason or "failed (no reason given)"
    out = [f'<details class="failure" open><summary>{_badge_html(FAILED)}  {_h(t.contract)}.{_h(t.name)}  '
           f'<span class="muted">{_h(t.kind)}</span></summary>']
    rows = [("suite", _h(t.suite)), ("reason", _h(reason))]
    if t.runs is not None or t.calls is not None:
        rows.append(("campaign", _h(f"{_num(t.runs)} runs, {_num(t.calls)} calls, {_num(t.reverts)} reverts")))
    if t.sequence:
        shrunk = f" (shrunk from {t.shrunk_from})" if t.shrunk_from and t.shrunk_from != len(t.sequence) else ""
        rows.append(("counter-example", _h(f"{len(t.sequence)} call(s){shrunk}")))
    if t.note:
        rows.append(("note", _h(t.note)))
    out.append(_kv(rows))

    frames = trace_frames(t.traces)
    used: set[int] = set()

    def take(func: str, contract: str | None) -> Frame | None:
        for k, f in enumerate(frames):
            if k not in used and f.func == func and (not contract or f.contract == contract):
                used.add(k)
                return f
        return None

    if t.sequence:
        out.append("<h3>Call sequence</h3><ol class=\"tree\">")
        for i, c in enumerate(t.sequence, 1):
            out.append(_call_node(i, c, _param_names(root, c, cache), take(c.function, c.target)))
        if t.kind == "invariant":
            out.append(_check_node(t, len(t.sequence) + 1, take(t.func, t.contract)))
        out.append("</ol>")
    else:
        out.append('<p class="muted">forge did not print a call sequence for this failure.</p>')
    loose = [s for k, f in enumerate(frames) if k not in used for s in f.storage]
    if loose:
        out.append("<details><summary>Storage changes in other trace frames</summary>" + _storage_rows(loose) + "</details>")
    snippet = replay_snippet(t)
    if snippet:
        out.append(f"<details><summary>Replay as a Foundry regression test</summary><p>Paste into {_h(t.contract)} "
                   f"({_h(t.file)}) and run it with -vvvv.</p><pre>{_h(snippet)}</pre></details>")
    out.append("<details><summary>Rerun this test</summary><pre>"
               + _h(f"forge test --match-path '{t.file}' --match-contract '{t.contract}' --match-test '{t.func}' -vvvv")
               + "</pre></details>")
    if t.logs:
        out.append(f"<details><summary>Logs ({len(t.logs)} lines)</summary><pre>{_h(chr(10).join(t.logs))}</pre></details>")
    if t.traces:
        out.append(f"<details><summary>Traces ({len(t.traces)} lines)</summary><pre>{_h(chr(10).join(t.traces))}</pre></details>")
    out.append("</details>")
    return "".join(out)


def render_html(run: Run, root: Path | None = None, generated: str | None = None) -> str:
    """The same results as ``render``, as one standalone HTML page with no scripts or external files."""
    root = root or Path(".")
    generated = generated or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    m = metrics(run)
    suites = run.suites()
    time_label = ("wall clock, forge" if m.wall_time is not None
                  else "sum of suite durations" if m.suite_time is not None else "not reported by forge")
    out = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>FoundryGuard Report</title><style>{HTML_CSS}</style></head><body><main>",
           f"<h1>FoundryGuard Report  {_badge_html(run.status)}</h1>",
           f'<p class="sub">Generated {_h(generated)} from {_h(run.source)} ({_h(run.fmt)})</p>']
    if not run.tests:
        out.append("<p><b>No test results were found in the forge output.</b> Did the suites compile and run?</p>")
    elif m.failed:
        out.append(f"<p><b>{m.failed} of {m.tests} test(s) failed.</b> Each call sequence below is the shrunk "
                   "counter-example forge found.</p>")
    else:
        out.append(f"<p><b>All {m.passed} test(s) passed</b> across {m.suites} suite(s).</p>")

    out.append("<h2>Metrics</h2><table>")
    out.append('<tr><th>Metric</th><th class="n">Value</th><th>Detail</th></tr>')
    rows = [
        ("Invariants checked", _num(m.invariants), f"{m.invariants_broken} broken, {m.campaigns} campaign(s)"),
        ("Fuzz inputs", _num(m.fuzz_inputs), f"{_num(m.invariant_calls)} invariant calls + {_num(m.fuzz_runs)} fuzz runs"),
        ("Invariant runs", _num(m.invariant_runs), "call sequences generated"),
        ("Execution time", format_seconds(m.time), time_label),
        ("Tests", _num(m.tests), f"{m.passed} passed, {m.failed} failed, {m.skipped} skipped"),
        ("Suites", _num(m.suites), ""),
    ]
    out += [f'<tr><td>{_h(a)}</td><td class="n">{_h(b)}</td><td>{_h(c)}</td></tr>' for a, b, c in rows]
    out.append("</table>")

    out.append('<h2>Suites</h2><table><tr><th>Suite</th><th>Status</th><th class="n">Passed</th><th class="n">Failed</th>'
               '<th class="n">Skipped</th><th class="n">Time</th></tr>')
    for sid, tests in suites.items():
        st = FAILED if any(t.status == FAILED for t in tests) else PASSED
        out.append(f"<tr><td>{_h(sid.rpartition(':')[2])}</td><td>{_badge_html(st)}</td>"
                   f'<td class="n">{sum(t.status == PASSED for t in tests)}</td><td class="n">{sum(t.status == FAILED for t in tests)}</td>'
                   f'<td class="n">{sum(t.status == SKIPPED for t in tests)}</td><td class="n">{format_seconds(run.suite_time.get(sid))}</td></tr>')
    out.append("</table>")

    if run.failures:
        out.append("<h2>Failed execution paths</h2>")
        cache: dict = {}
        out += [_failure_html(t, root, cache) for t in run.failures]

    out.append("<h2>All tests</h2>")
    for sid, tests in suites.items():
        out.append(f"<h3>{_h(sid)}</h3><table><tr><th>Status</th><th>Test</th><th>Kind</th><th class=\"n\">Runs</th>"
                   '<th class="n">Calls</th><th class="n">Reverts</th><th class="n">Gas</th></tr>')
        for t in tests:
            note = f'<br><span class="muted">{_h(t.note)}</span>' if t.note else ""
            out.append(f"<tr><td>{_badge_html(t.status)}</td><td>{_h(t.name)}{note}</td><td>{_h(t.kind)}</td>"
                       f'<td class="n">{_num(t.runs)}</td><td class="n">{_num(t.calls)}</td>'
                       f'<td class="n">{_num(t.reverts)}</td><td class="n">{_num(t.gas)}</td></tr>')
        out.append("</table>")
    out.append("<footer>Generated by FoundryGuard. A passing invariant held for every call sequence forge tried; "
               "it is evidence, not a proof.</footer></main></body></html>")
    return "\n".join(out) + "\n"


def load_persisted_sequences(run: Run, root: Path, cache_dir: str = "cache") -> None:
    """Fill missing counter-examples from forge's persisted failures.

    Forge 1.x prints no ``[Sequence]`` for a shared invariant campaign, but it stores the shrunk call
    sequence of every broken invariant in ``cache/invariant/failures/<TestContract>/invariants/<invariant>``
    (older forge: ``cache/invariant/failures/<TestContract>/<invariant>``).
    """
    failures_dir = root / cache_dir / "invariant" / "failures"
    for t in run.failures:
        if t.sequence or t.kind != "invariant":
            continue
        base = failures_dir / t.contract
        candidates = [base / "invariants" / t.func, base / t.func]
        # Other forge versions nest the file differently; any file named after the invariant under a
        # directory of this test contract is the same record.
        if failures_dir.is_dir():
            found = sorted(failures_dir.rglob(f"{t.func}*"), key=lambda q: (t.contract not in q.parts, len(q.parts)))
            candidates += [q for q in found if q.is_file() and q.name.split(".")[0] == t.func]
        data = path = None
        for path in candidates:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                break
            except (OSError, ValueError):
                data = None
        if data is None:
            continue
        seq = data
        if isinstance(data, dict):
            seq = next((data[k] for k in ("call_sequence", "sequence", "calls") if isinstance(data.get(k), list)), None)
        if isinstance(seq, list):
            t.sequence = [_call_from_json(step) for step in seq if isinstance(step, dict)]
            if t.sequence:
                t.note = (t.note + "; " if t.note else "") + f"counter-example read from `{path.relative_to(root).as_posix()}`"


def html_path(root: Path, output: str | None = None, html: str | None = None) -> Path:
    """Where the HTML report goes: ``html`` if given, else next to the Markdown report."""
    if html:
        p = Path(html)
        return p if p.is_absolute() else Path.cwd() / p
    md = Path(output) if output else root / REPORT_FILE
    if not md.is_absolute() and output:
        md = Path.cwd() / md
    return md.parent / HTML_FILE


def write_report(run: Run, root: Path, output: str | None = None, html: str | None | bool = None) -> Path:
    """Write the Markdown report and, unless ``html`` is False, ``foundryguard-report.html`` beside it
    (or at the path ``html`` names). Returns the Markdown path."""
    resolve_from_source(run, root)
    load_persisted_sequences(run, root)
    path = Path(output) if output else root / REPORT_FILE
    if not path.is_absolute() and output:
        path = Path.cwd() / path
    path.parent.mkdir(parents=True, exist_ok=True)
    generated = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    path.write_text(render(run, root, generated))
    if html is not False:
        hp = html_path(root, output, html if isinstance(html, str) else None)
        hp.parent.mkdir(parents=True, exist_ok=True)
        hp.write_text(render_html(run, root, generated), encoding="utf-8")
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
    ap.add_argument("--html", help=f"HTML report path (default: {HTML_FILE} next to the Markdown report)")
    ap.add_argument("--no-html", action="store_true", help=f"do not write {HTML_FILE}")
    ap.add_argument("--fail-on-failure", action="store_true", help="exit 1 if a test failed or no results were found")
    args = ap.parse_args(argv)
    run = load(args.results)
    path = write_report(run, Path(args.root), args.output, False if args.no_html else args.html)
    print(f"foundryguard: {path} [{run.status}] {run.count(PASSED)} passed, {run.count(FAILED)} failed, "
          f"{run.count(SKIPPED)} skipped", file=sys.stderr)
    if args.fail_on_failure and (run.status != PASSED):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
