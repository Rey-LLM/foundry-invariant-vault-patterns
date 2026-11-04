"""Layer 10 tests: scoring engine, simulation pipeline and the desktop window's headless logic."""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import compiler  # noqa: E402
import foundryguard  # noqa: E402
import gui  # noqa: E402
import scoring  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCORING = FIXTURES / "scoring"
FORGE_STDOUT = FIXTURES / "forge" / "leaky-stdout.txt"

REQUIRE_SOLC = os.environ.get("FOUNDRYGUARD_REQUIRE_SOLC") == "1"
HAVE_SOLC = REQUIRE_SOLC or bool(compiler.discover_compilers())
needs_solc = unittest.skipUnless(HAVE_SOLC, "no solc / solcjs on this machine")


def rules_at(result: scoring.ScoreResult, file_suffix: str) -> set[tuple[str, int]]:
    return {(f.rule, f.line) for f in result.findings if f.file.endswith(file_suffix)}


class TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="foundryguard-l10-"))
        self.root = self.tmp / "project"
        shutil.copytree(SCORING, self.root)
        self.out = self.tmp / "report"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


class ScoringRuleTests(TmpCase):
    def test_weak_vault_deductions_carry_exact_lines(self):
        result, _ = scoring.score_path(self.root / "src" / "WeakVault.sol")
        got = rules_at(result, "WeakVault.sol")
        expected = {
            ("SOL-FLOATING-PRAGMA", 2),
            ("SOL-UNPROTECTED-MUTATION", 30),   # setFee: feeBps = newFee
            ("SOL-INPUT-VALIDATION", 29),
            ("SOL-TX-ORIGIN", 34),
            ("SOL-UNPROTECTED-MUTATION", 35),   # setOwner: tx.origin is not access control
            ("SOL-ZERO-ADDRESS", 35),
            ("SOL-DONATION-DRIFT", 39),
            ("SOL-CEI-DRIFT", 41),              # shares written after transferFrom
            ("SOL-CEI-DRIFT", 49),              # shares written after call{value:}
            ("SOL-UNCHECKED-CALL", 54),
            ("SOL-SPOT-PRICE", 58),
            ("SOL-DIV-BY-TOTAL", 63),
            ("SOL-MUTABILITY", 66),
            ("SOL-PAYABLE-UNUSED", 70),
            ("SOL-TRANSIENT-LEAK", 80),
        }
        self.assertTrue(expected <= got, expected - got)
        self.assertEqual(result.score, 1)
        self.assertEqual(result.verdict, "BREACHED")
        layers = {f.rule: (f.severity, f.layer) for f in result.findings}
        self.assertEqual(layers["SOL-TX-ORIGIN"], ("CRITICAL", "L2"))
        self.assertEqual(layers["SOL-CEI-DRIFT"], ("HIGH", "L4"))
        self.assertEqual(layers["SOL-MUTABILITY"], ("LOW", "L3"))
        cei = [f for f in result.findings if f.rule == "SOL-CEI-DRIFT"]
        self.assertEqual({f.preset for f in cei}, {4, 8})  # token pull vs native payout

    def test_hardened_vault_is_clean(self):
        result, _ = scoring.score_path(self.root / "src" / "HardenedVault.sol")
        self.assertEqual(result.findings, [], [(f.rule, f.line) for f in result.findings])
        self.assertEqual(result.score, 100)
        self.assertEqual(result.verdict, "HARDENED")

    def test_backend_rules(self):
        result, _ = scoring.score_path(self.root / "backend" / "app.py")
        got = rules_at(result, "app.py")
        expected = {("WEB-SECRET", 9), ("WEB-GLOBAL-STATE", 15), ("WEB-INPUT-VALIDATION", 17), ("WEB-SQL", 19),
                    ("WEB-DESERIALIZE", 24), ("WEB-COMMAND", 29), ("WEB-TLS-OFF", 30), ("WEB-OPEN-REDIRECT", 35),
                    ("WEB-MUTABLE-DEFAULT", 38), ("WEB-DEBUG", 44)}
        self.assertTrue(expected <= got, expected - got)
        self.assertEqual(result.kind, "web")

    def test_validation_library_silences_input_rule(self):
        app = self.root / "backend" / "app.py"
        app.write_text("from pydantic import BaseModel\n" + app.read_text())
        result, _ = scoring.score_path(app)
        self.assertNotIn("WEB-INPUT-VALIDATION", {f.rule for f in result.findings})

    def test_html_rules(self):
        result, _ = scoring.score_path(self.root / "web" / "index.html")
        got = rules_at(result, "index.html")
        expected = {("WEB-NO-SRI", 4), ("WEB-CSRF", 7), ("WEB-INPUT-VALIDATION", 12), ("WEB-XSS", 13),
                    ("WEB-TOKEN-STORAGE", 14)}
        self.assertTrue(expected <= got, expected - got)

    def test_comments_do_not_count(self):
        p = self.root / "src" / "Commented.sol"
        p.write_text("// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ncontract C {\n"
                     "    // require(tx.origin == owner);\n    /* selfdestruct(payable(msg.sender)); */\n"
                     "    function f() external pure returns (uint256) { return 1; }\n}\n")
        result, _ = scoring.score_path(p)
        self.assertEqual(result.findings, [])

    def test_every_finding_is_actionable(self):
        result, _ = scoring.score_path(self.root)
        self.assertGreater(len(result.findings), 25)
        for f in result.findings:
            self.assertIn(f.severity, scoring.SEVERITIES)
            self.assertIn(f.layer, scoring.LAYERS)
            self.assertTrue(f.mitigation and f.title and f.file, f)
            self.assertGreaterEqual(f.line, 1, f)

    def test_presets_switch_their_rules_off(self):
        on, _ = scoring.score_path(self.root / "src")
        off, _ = scoring.score_path(self.root / "src", presets=scoring.ALL_PRESETS - {5, 6})
        self.assertIn("SOL-TRANSIENT-LEAK", {f.rule for f in on.findings})
        self.assertIn("SOL-SPOT-PRICE", {f.rule for f in on.findings})
        self.assertNotIn("SOL-TRANSIENT-LEAK", {f.rule for f in off.findings})
        self.assertNotIn("SOL-SPOT-PRICE", {f.rule for f in off.findings})
        self.assertIn("SOL-TX-ORIGIN", {f.rule for f in off.findings})  # base rules are never switched off

    def test_skips_tests_and_dependencies(self):
        for d in ("test", "lib", "node_modules"):
            (self.root / d).mkdir(exist_ok=True)
            (self.root / d / "Bad.sol").write_text("pragma solidity ^0.8.0;\ncontract B { function f() external { require(tx.origin != address(0)); } }\n")
        (self.root / "src" / "X.t.sol").write_text("pragma solidity ^0.8.0;\ncontract T { function f() external { require(tx.origin != address(0)); } }\n")
        files = {p.name for p in scoring.discover(self.root)}
        self.assertEqual(files, {"WeakVault.sol", "HardenedVault.sol", "app.py", "index.html"})


class ScoreMathTests(unittest.TestCase):
    def f(self, rule: str, sev: str) -> scoring.Finding:
        return scoring.Finding(rule, sev, "L1", "t", "a.sol", 1, "", "m")

    def test_weights_cap_and_floor(self):
        self.assertEqual(scoring.score([]), 100)
        self.assertEqual(scoring.score([self.f("A", "LOW")]), 97)
        self.assertEqual(scoring.score([self.f("A", "MEDIUM"), self.f("B", "HIGH")]), 77)
        many = [self.f("A", "HIGH") for _ in range(10)]
        self.assertEqual(scoring.score(many), 100 - 15 * scoring.RULE_CAP)
        self.assertEqual([x.points for x in many].count(0), 10 - scoring.RULE_CAP)
        self.assertEqual(scoring.score([self.f(str(i), "CRITICAL") for i in range(9)]), 1)

    def test_verdicts(self):
        self.assertEqual([scoring.verdict(s) for s in (100, 90, 89, 75, 74, 50, 49, 25, 24, 1)],
                         ["HARDENED", "HARDENED", "ACCEPTABLE", "ACCEPTABLE", "EXPOSED", "EXPOSED",
                          "CRITICAL", "CRITICAL", "BREACHED", "BREACHED"])

    def test_parse_presets(self):
        self.assertEqual(scoring.parse_presets("all"), scoring.ALL_PRESETS)
        self.assertEqual(scoring.parse_presets("none"), frozenset())
        self.assertEqual(scoring.parse_presets("1, 5,8"), frozenset({1, 5, 8}))
        with self.assertRaises(ValueError):
            scoring.parse_presets("9")


class _Page(http.server.BaseHTTPRequestHandler):
    hits = 0
    body = (b"<!doctype html><html><body>\n<form method=\"POST\" action=\"/x\"><input name=a></form>\n"
            b"<script>el.innerHTML = location.hash;</script>\n</body></html>\n")

    def do_GET(self):  # noqa: N802
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sid=abc; Path=/")
        self.send_header("X-Powered-By", "Express 4.17.1")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


class UrlTests(TmpCase):
    def test_single_passive_get(self):
        _Page.hits = 0
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Page)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({})).open
            result, page = scoring.simulate(url, out_dir=self.out, opener=opener)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(_Page.hits, 1)
        rules = {f.rule for f in result.findings}
        self.assertTrue({"URL-NO-TLS", "URL-NO-CSP", "URL-CLICKJACKING", "URL-NO-NOSNIFF", "URL-COOKIE-FLAGS",
                         "URL-VERSION-LEAK", "WEB-CSRF", "WEB-XSS"} <= rules, rules)
        self.assertEqual(result.kind, "url")
        self.assertEqual(result.matrix, [])
        self.assertTrue(any("nothing was fuzzed" in n for n in result.notes))
        xss = next(f for f in result.findings if f.rule == "WEB-XSS")
        self.assertEqual(xss.line, 3)
        self.assertIn('id="score"', page.read_text())

    def test_is_url(self):
        self.assertTrue(scoring.is_url("https://example.com/app"))
        self.assertFalse(scoring.is_url("example.com"))
        self.assertFalse(scoring.is_url("file:///etc/passwd"))
        self.assertTrue(str(scoring.default_report_dir("https://a.example:8443/x")).endswith(
            os.path.join("foundryguard-reports", "a.example_8443")))


class SimulateTests(TmpCase):
    def test_report_has_score_badge_first(self):
        logs: list[str] = []
        with unittest.mock.patch.object(scoring, "_blueprint_matrix", return_value=(None, "AST unavailable (test)")):
            result, page = scoring.simulate(str(self.root), run_forge=False, out_dir=self.out, progress=logs.append)
        html = page.read_text()
        self.assertEqual(page.name, "foundryguard-report.html")
        self.assertLess(html.index('<div class="scorebox" id="score"><div class="num">1<small>/100</small>'),
                        html.index("<h1>"))
        for section in ("Deductions", "Mitigation plan", "Simulation matrix"):
            self.assertIn(f"<h2>{section}</h2>", html)
        self.assertIn("src/WeakVault.sol:34", html)
        rows = {r.contract: r for r in result.matrix}
        self.assertEqual(rows["WeakVault"].cells[6], "FLAGGED")
        self.assertEqual(rows["LeakyLock"].cells[5], "FLAGGED")
        self.assertEqual(rows["HardenedVault"].cells[5], "clear")
        data = json.loads((self.out / scoring.SCORE_JSON).read_text())
        self.assertEqual(data["score"], result.score)
        self.assertEqual(data["counts"]["CRITICAL"], result.counts()["CRITICAL"])
        self.assertTrue(any(m.startswith("Score 1/100") for m in logs))

    def test_presets_off_show_in_matrix(self):
        with unittest.mock.patch.object(scoring, "_blueprint_matrix", return_value=(None, "AST unavailable (test)")):
            result, _ = scoring.simulate(str(self.root), presets={1, 2}, run_forge=False, out_dir=self.out)
        self.assertEqual(result.matrix[0].cells[5], "off")
        self.assertEqual(result.presets, [1, 2])

    @needs_solc
    def test_matrix_from_ast(self):
        result, _ = scoring.simulate(str(self.root), run_forge=False, out_dir=self.out)
        rows = {r.contract: r for r in result.matrix}
        self.assertEqual(rows["WeakVault"].source, "ast")
        self.assertEqual(rows["WeakVault"].cells[6], "ARMED")   # Preset 06 detector on balanceOf(this)
        self.assertEqual(rows["WeakVault"].cells[8], "ARMED")   # Preset 08: native payout before settlement
        self.assertEqual(rows["HardenedVault"].cells[8], "clear")
        self.assertFalse([n for n in result.notes if n.startswith("AST unavailable")])

    def test_forge_failures_become_critical_deductions(self):
        lines = FORGE_STDOUT.read_text().splitlines(keepends=True)

        class FakeProc:
            def __init__(self, *a, **kw):
                self.stdout = iter(lines)

            def wait(self):
                return 1

            def kill(self):
                pass

        with unittest.mock.patch.object(scoring.shutil, "which", return_value="/usr/bin/forge"), \
                unittest.mock.patch.object(scoring.subprocess, "Popen", FakeProc), \
                unittest.mock.patch.object(scoring, "_blueprint_matrix", return_value=(None, "AST unavailable (test)")):
            result, page = scoring.simulate(str(self.root / "src" / "HardenedVault.sol"), out_dir=self.out)
        broken = [f for f in result.findings if f.rule == "FUZZ-INVARIANT-BROKEN"]
        self.assertTrue(broken)
        self.assertTrue(all(f.severity == "CRITICAL" and f.layer == "L10" for f in broken))
        self.assertGreater(result.forge["failed"], 0)
        self.assertLess(result.score, 100)
        self.assertIn("<h2>Fuzz campaign</h2>", page.read_text())

    def test_cancel(self):
        with self.assertRaises(scoring.Cancelled):
            scoring.simulate(str(self.root), run_forge=False, out_dir=self.out, cancel=lambda: True)

    def test_cli_score_and_min_score(self):
        with unittest.mock.patch.object(scoring, "_blueprint_matrix", return_value=(None, "x")), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            rc_bad = foundryguard.main(["score", str(self.root / "src" / "WeakVault.sol"), "--out", str(self.out),
                                        "--min-score", "50"])
            rc_ok = foundryguard.main(["score", str(self.root / "src" / "HardenedVault.sol"), "--out", str(self.out),
                                       "--min-score", "90", "--presets", "1,2,3"])
        self.assertEqual((rc_bad, rc_ok), (1, 0))
        self.assertIn("1/100 BREACHED", out.getvalue())
        self.assertIn("100/100 HARDENED", out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(foundryguard.main(["score", str(self.root / "missing"), "--out", str(self.out)]), 2)
            self.assertEqual(foundryguard.main(["score", str(self.root), "--presets", "12"]), 2)


class GuiLogicTests(TmpCase):
    def test_describe_target(self):
        self.assertFalse(gui.describe_target("")[0])
        self.assertTrue(gui.describe_target("https://example.com")[0])
        self.assertFalse(gui.describe_target("ftp://example.com")[0])
        self.assertFalse(gui.describe_target(str(self.root / "nope"))[0])
        (self.root / "notes.txt").write_text("x")
        self.assertFalse(gui.describe_target(str(self.root / "notes.txt"))[0])
        ok, text = gui.describe_target(str(self.root))
        self.assertTrue(ok)
        self.assertIn("Foundry project", text)
        self.assertIn("2 Solidity", text)

    def wait(self, job: gui.Job) -> list[gui.Event]:
        job.thread.join(10)
        return job.drain()

    def test_job_runs_in_background_and_reports(self):
        seen = {}

        def runner(target, presets, run_forge, out_dir, progress, cancel):
            seen.update(thread=threading.current_thread().name, presets=presets, forge=run_forge)
            progress("working")
            r = scoring.ScoreResult(target, "solidity", 63, [])
            return r, self.out / "foundryguard-report.html"

        events = self.wait(gui.Job("x", frozenset({5}), False, runner=runner).start())
        self.assertEqual([e.kind for e in events], ["log", "done"])
        self.assertEqual(events[1].text, "63/100 EXPOSED")
        self.assertEqual(seen, {"thread": "foundryguard-simulation", "presets": frozenset({5}), "forge": False})

    def test_job_errors_and_cancel(self):
        def boom(*a, **kw):
            raise FileNotFoundError("gone")
        events = self.wait(gui.Job("x", frozenset(), runner=boom).start())
        self.assertEqual(events[-1].kind, "error")
        self.assertIn("gone", events[-1].text)

        def slow(target, presets, run_forge, out_dir, progress, cancel):
            while not cancel():
                time.sleep(0.01)
            raise scoring.Cancelled("cancelled")
        job = gui.Job("x", frozenset(), runner=slow).start()
        job.cancel()
        events = self.wait(job)
        self.assertEqual(events[-1].text, "Stopped: cancelled")

    def test_job_with_real_pipeline(self):
        with unittest.mock.patch.object(scoring, "_blueprint_matrix", return_value=(None, "x")):
            job = gui.Job(str(self.root), scoring.ALL_PRESETS, False, out_dir=str(self.out)).start()
            events = self.wait(job)
        done = events[-1]
        self.assertEqual(done.kind, "done", [e.text for e in events])
        self.assertEqual(done.result.score, 1)
        self.assertTrue(done.report.is_file())

    def test_open_report_uses_file_uri(self):
        opened = []
        p = self.out / "foundryguard-report.html"
        gui.open_report(p, lambda u: opened.append(u) or True)
        self.assertTrue(opened[0].startswith("file://") and opened[0].endswith("foundryguard-report.html"))

    def test_main_without_tk(self):
        with unittest.mock.patch.dict(sys.modules, {"tkinter": None}), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(gui.main([]), 2)
        self.assertIn("python3-tk", err.getvalue())

    def test_main_without_customtkinter(self):
        try:
            import tkinter  # noqa: F401
        except ImportError:
            self.skipTest("Tk not available")
        with unittest.mock.patch.dict(sys.modules, {"customtkinter": None}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(gui.main([]), 2)
        self.assertIn("pip install customtkinter", err.getvalue())

    def test_customtkinter_dependency(self):
        self.assertIn('"customtkinter>=5.2"', (REPO / "pyproject.toml").read_text())

    def test_score_color(self):
        self.assertEqual(gui.score_color(100), gui.ACCENT)
        self.assertEqual(gui.score_color(60), gui.AMBER)
        self.assertEqual(gui.score_color(10), gui.RED)

    def test_entry_point(self):
        text = (REPO / "pyproject.toml").read_text()
        self.assertIn('foundryguard-gui = "foundryguard.gui:main"', text)


def _tk_root():
    try:
        return gui.make_root()
    except Exception:
        return None


@unittest.skipUnless(os.environ.get("DISPLAY") or sys.platform in ("darwin", "win32"), "no display")
class GuiWindowTests(TmpCase):
    def test_window_launches_and_shows_score(self):
        root = _tk_root()
        if root is None:
            self.skipTest("Tk not available")
        try:
            app = gui.App(root, str(self.root))
            self.assertEqual(str(app.launch_btn.cget("text")), gui.LAUNCH_LABEL)
            self.assertEqual(app.entry.get(), str(self.root))
            app.target_var.set("https://example.com")
            self.assertEqual(app.entry.get(), "https://example.com")
            app.target_var.set(str(self.root))
            self.assertEqual(len(app.preset_vars), 8)
            app.preset_vars[3].set(False)
            self.assertEqual(app.selected_presets(), scoring.ALL_PRESETS - {3})
            app.open_var.set(False)
            app.runner = lambda target, presets, **kw: (scoring.ScoreResult(target, "solidity", 63, []),
                                                        self.out / "r.html")
            app.launch()
            deadline = time.time() + 10
            while app.score_var.get() != "63/100" and time.time() < deadline:
                root.update()
                time.sleep(0.02)
            self.assertEqual(app.score_var.get(), "63/100")
            self.assertIn("EXPOSED", app.status_var.get())
            self.assertEqual(app.verdict_var.get(), "EXPOSED")
            self.assertEqual(app.progress.get(), 1)
            app.target_var.set("")
            app.update_hint()
            self.assertEqual(str(app.launch_btn.cget("state")), "disabled")
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
