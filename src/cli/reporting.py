#!/usr/bin/env python3
"""FoundryGuard reporting: Markdown summaries and SARIF for CI.

* ``markdown_report`` - what was generated, per contract (good for ``$GITHUB_STEP_SUMMARY``).
* ``sarif_from_generation`` - setup warnings, placeholders and skipped functions as SARIF notes.
* ``sarif_from_forge`` - failed invariants from ``forge test --json`` as SARIF errors that point
  at the failing ``invariant_*`` function, so they show up as code-scanning alerts on a PR.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL = {"name": "FoundryGuard", "informationUri": "https://github.com/Rey-LLM/foundry-invariant-vault-patterns"}


def markdown_report(report: list[dict], blueprint: dict | None = None) -> str:
    out = ["# FoundryGuard report", ""]
    if blueprint:
        s = blueprint.get("summary", {})
        out.append(f"Scanned {s.get('files_scanned', 0)} file(s) with the `{blueprint.get('backend', 'regex')}` backend: "
                   f"{s.get('contracts', 0)} contract(s), {s.get('deposit_functions', 0)} deposit, "
                   f"{s.get('withdraw_functions', 0)} withdraw, {s.get('stake_lock_functions', 0)} stake/lock function(s).")
        out.append("")
    if not report:
        out.append("No contract with drivable deposit / withdraw / staking functions was found.")
        return "\n".join(out) + "\n"
    out.append("| Contract | Flows | Invariants | Tokens | Status |")
    out.append("| :-- | --: | :-- | :-- | :-- |")
    for r in report:
        invs = ", ".join(f"`{i}`" for i in r.get("invariants", [])) or "-"
        toks = ", ".join(f"{t['var']} ({t['role']})" for t in r.get("tokens", [])) or "-"
        status = "blocked" if r.get("blocked") else f"handler {r.get('handler')}, test {r.get('invariant')}"
        kind = " (ERC-4626)" if r.get("erc4626") else (" (upgradeable)" if r.get("upgradeable") else "")
        if r.get("hooks"):
            kind += " (hooks)"
        out.append(f"| `{r['contract']}`{kind} | {len(r.get('flows', []))} | {invs} | {toks} | {status} |")
    notes = [(r["contract"], n) for r in report
             for n in r.get("blocked", []) + r.get("warnings", []) + r.get("setup_notes", []) + r.get("skipped", [])]
    if notes:
        out += ["", "## Needs attention", ""]
        out += [f"- **{c}**: {n}" for c, n in notes]
    return "\n".join(out) + "\n"


def _result(rule: str, level: str, message: str, uri: str, line: int) -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                            "region": {"startLine": max(int(line or 1), 1)}}}],
    }


def _sarif(results: list[dict], rules: dict[str, str]) -> dict:
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {**TOOL, "rules": [{"id": k, "shortDescription": {"text": v}} for k, v in rules.items()]}},
            "results": results,
        }],
    }


def sarif_from_generation(report: list[dict], root: Path) -> dict:
    rules = {
        "foundryguard/blocked": "Suite not generated: setUp needs input",
        "foundryguard/missing-parent": "Parent contract source not found",
        "foundryguard/placeholder": "setUp uses a placeholder argument",
        "foundryguard/skipped-function": "Value-flow function not fuzzed",
    }
    results = []
    for r in report:
        uri, line = r.get("file", ""), r.get("line", 1)
        for b in r.get("blocked", []):
            results.append(_result("foundryguard/blocked", "warning", f"{r['contract']}: {b}", uri, line))
        for w in r.get("warnings", []):
            results.append(_result("foundryguard/missing-parent", "warning", f"{r['contract']}: {w}", uri, line))
        for n in r.get("setup_notes", []):
            results.append(_result("foundryguard/placeholder", "note", f"{r['contract']}: {n}", uri, line))
        for s in r.get("skipped", []):
            results.append(_result("foundryguard/skipped-function", "note", f"{r['contract']}: {s}", uri, line))
    return _sarif(results, rules)


def _find_line(path: Path, func: str) -> int:
    try:
        for i, text in enumerate(path.read_text().splitlines(), 1):
            if re.search(rf"\bfunction\s+{re.escape(func)}\s*\(", text):
                return i
    except OSError:
        pass
    return 1


EVENTS_KEY = "__foundryguard_events__"


def failed_tests(forge_json: dict) -> list[tuple[str, str, str, str]]:
    """Return (file, contract, test, reason) for every failed test in ``forge test --json`` output."""
    out = []
    # Current forge runs every invariant of a contract in one shared campaign and files the campaign
    # under the first invariant's name; the invariant that actually broke is in a separate
    # {"event": "failure", "invariant": ...} line. Prefer those events when present.
    events: dict[str, list[dict]] = {}
    for ev in forge_json.get(EVENTS_KEY, []):
        events.setdefault(ev.get("target", ""), []).append(ev)
    for suite_id, suite in forge_json.items():
        if not isinstance(suite, dict) or suite_id == EVENTS_KEY:
            continue
        file, _, contract = suite_id.rpartition(":")
        if suite_id in events:
            for ev in events.pop(suite_id):
                out.append((file, contract, f"{ev.get('invariant', '?')}()", ev.get("reason") or "failed"))
            continue
        for test, res in (suite.get("test_results") or {}).items():
            if not isinstance(res, dict) or str(res.get("status", "")).lower() not in ("failure", "failed", "fail"):
                continue
            reason = res.get("reason") or "failed"
            counter = res.get("counterexample")
            if isinstance(counter, dict) and counter.get("Sequence"):
                calls = []
                for step in counter["Sequence"][:20]:
                    if isinstance(step, dict):
                        calls.append(step.get("signature") or step.get("calldata") or "?")
                if calls:
                    reason += " | sequence: " + " -> ".join(str(c) for c in calls)
            out.append((file, contract, test, reason))
    for target, evs in events.items():  # events whose suite had no result entry
        file, _, contract = target.rpartition(":")
        out += [(file, contract, f"{ev.get('invariant', '?')}()", ev.get("reason") or "failed") for ev in evs]
    return out


def sarif_from_forge(forge_json: dict, root: Path) -> dict:
    results = []
    for file, contract, test, reason in failed_tests(forge_json):
        func = test.split("(")[0]
        line = _find_line(root / file, func) if file else 1
        results.append(_result("foundryguard/invariant-broken", "error",
                               f"{contract}.{func} failed: {reason}", file or contract, line))
    return _sarif(results, {"foundryguard/invariant-broken": "A FoundryGuard invariant or test failed"})


def test_count(forge_json: dict) -> int:
    return sum(len((s or {}).get("test_results") or {}) for k, s in forge_json.items()
               if isinstance(s, dict) and k != EVENTS_KEY)


def markdown_from_forge(forge_json: dict) -> str:
    failed = failed_tests(forge_json)
    total = test_count(forge_json)
    out = ["# FoundryGuard test results", "", f"{total - len({(c, f) for f, c, _, _ in failed})} of {total} result(s) passed "
           "(forge checks all invariants of a contract in one shared campaign).", ""]
    if failed:
        out += ["| Contract | Test | Reason |", "| :-- | :-- | :-- |"]
        out += [f"| `{c}` | `{t}` | {r.replace('|', '/')} |" for _, c, t, r in failed]
        out.append("")
    out += ["<details><summary>All tests</summary>", ""]
    for suite_id, suite in sorted(forge_json.items()):
        if not isinstance(suite, dict) or suite_id == EVENTS_KEY:
            continue
        contract = suite_id.rpartition(":")[2]
        for test, res in sorted((suite.get("test_results") or {}).items()):
            status = res.get("status", "?") if isinstance(res, dict) else "?"
            out.append(f"- `{contract}.{test}`: {status}")
    out += ["", "</details>"]
    return "\n".join(out) + "\n"


def load_forge_json(path: Path) -> dict:
    text = path.read_text()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some forge versions print one JSON object per line.
        merged: dict = {}
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and obj.get("event") == "failure" and "invariant" in obj:
                    merged.setdefault(EVENTS_KEY, []).append(obj)
                elif isinstance(obj, dict):
                    merged.update(obj)
        return merged
