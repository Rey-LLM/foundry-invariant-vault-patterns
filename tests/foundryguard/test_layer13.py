"""Layer 13 tests: signature database, severity mapping, foundryguard.toml [score], init and entry points."""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import compiler  # noqa: E402
import foundryguard  # noqa: E402
import scoring  # noqa: E402
import signatures  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "signatures"

EXPECTED_WEAK = {
    ("FG-01", "src/LotteryVault.sol", 21),
    ("FG-02", "src/LotteryVault.sol", 37),
    ("FG-03", "src/LotteryVault.sol", 20),
    ("FG-04", "src/LotteryVault.sol", 32),
    ("FG-05", "src/LotteryVault.sol", 43),
    ("FG-06", "src/LotteryVault.sol", 26),
    ("FG-06", "src/LotteryVault.sol", 38),
    ("FG-07", "src/LotteryVault.sol", 26),
    ("FG-08", "src/LotteryVault.sol", 34),
    ("FG-51", "backend/server.js", 7),
    ("FG-52", "backend/server.js", 14),
    ("FG-53", "backend/server.js", 8),
    ("FG-54", "backend/server.js", 13),
    ("FG-55", "backend/server.js", 10),
    ("FG-56", "backend/server.js", 21),
    ("FG-57", "backend/server.js", 4),
}


class CatalogTests(unittest.TestCase):
    def test_original_fifteen_signatures_with_score_weights(self):
        # The fifteen 0.14 signatures: FG-01..FG-08 kept their ids, the backend seven are FG-51..FG-57 since 0.15.
        sigs = [signatures.BY_ID[f"FG-{i:02d}"] for i in (*range(1, 9), *range(51, 58))]
        self.assertEqual(len({s.rule for s in sigs}), 15)
        self.assertEqual(sum(s.stack == "solidity" for s in sigs), 8)
        self.assertEqual(sum(s.stack == "backend" for s in sigs), 7)
        for s in sigs:
            self.assertIn(s.severity, ("CRITICAL", "HIGH"), s.id)
            self.assertTrue(s.mitigation and s.fix and s.ref, s.id)
        self.assertEqual(scoring.WEIGHTS["CRITICAL"], 25)
        self.assertEqual(scoring.WEIGHTS["HIGH"], 15)

    def test_bad_override_rejected(self):
        with self.assertRaises(ValueError):
            signatures.severity_overrides({"score": {"severity": {"FG-01": "SEVERE"}}})


class DetectionTests(unittest.TestCase):
    def test_weak_project_hits_every_signature(self):
        result, _ = scoring.score_path(FIXTURES / "weak", config=scoring.ScanConfig())
        got = {(f.signature, f.file, f.line) for f in result.findings if f.signature}
        self.assertTrue(EXPECTED_WEAK <= got, sorted(EXPECTED_WEAK - got))
        expected_ids = {sid for sid, _, _ in EXPECTED_WEAK}
        self.assertTrue(expected_ids <= {f.signature for f in result.findings if f.signature})
        for f in result.findings:
            if f.signature:
                sig = signatures.BY_ID[f.signature]
                if f.rule == sig.rule and sig.fixed:
                    self.assertEqual(f.severity, sig.severity, f.rule)
                self.assertEqual(f.fix, sig.fix)
                self.assertTrue(f.evidence and f.mitigation, f.rule)
        self.assertEqual(result.score, 1)

    def test_safe_project_is_clean(self):
        result, _ = scoring.score_path(FIXTURES / "safe", config=scoring.ScanConfig())
        self.assertEqual([(f.rule, f.location) for f in result.findings], [])
        self.assertEqual(result.score, 100)

    def test_each_signature_costs_its_weight(self):
        result, _ = scoring.score_path(FIXTURES / "weak" / "src" / "LotteryVault.sol", config=scoring.ScanConfig())
        tx = [f for f in result.findings if f.signature == "FG-03"]
        self.assertEqual([f.points for f in tx], [25])
        loop = [f for f in result.findings if f.signature == "FG-08"]
        self.assertEqual([f.points for f in loop], [15])

    def test_native_transfer_and_nft_transfer_are_not_erc20(self):
        src = """pragma solidity 0.8.24;
interface IERC721 { function transferFrom(address, address, uint256) external; }
contract Pay {
    IERC721 nft;
    function out(address payable to) external { require(msg.sender == to); to.transfer(1); }
    function pull(uint256 id) external { nft.transferFrom(msg.sender, address(this), id); }
}"""
        found, _ = scoring.check_solidity("Pay.sol", src, scoring.ALL_PRESETS)
        self.assertNotIn("SOL-ERC20-UNCHECKED", {f.rule for f in found})

    def test_arbitrary_from_needs_caller_chosen_source(self):
        src = """pragma solidity 0.8.24;
interface IERC20 { function transferFrom(address, address, uint256) external returns (bool); }
contract Pull {
    IERC20 t;
    function a(address from, uint256 x) external { require(from == msg.sender); require(t.transferFrom(from, address(this), x)); }
    function b(address from, uint256 x) external { require(t.transferFrom(from, address(this), x)); }
}"""
        found, _ = scoring.check_solidity("Pull.sol", src, scoring.ALL_PRESETS)
        hits = [f for f in found if f.rule == "SOL-ARBITRARY-FROM"]
        self.assertEqual([f.line for f in hits], [6])

    def test_limiter_elsewhere_in_project_covers_auth_routes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            shutil.copy(FIXTURES / "weak" / "backend" / "server.js", root / "server.js")
            (root / "limits.js").write_text('const rateLimit = require("express-rate-limit");\n'
                                            "module.exports = rateLimit({ max: 5 });\n")
            result, _ = scoring.score_path(root, config=scoring.ScanConfig())
            self.assertNotIn("FG-54", {f.signature for f in result.findings})

    def test_flask_body_cap(self):
        app = 'from flask import Flask, request\napp = Flask(__name__)\n@app.post("/x")\ndef x():\n    return request.get_json()\n'
        self.assertIn("WEB-BODY-LIMIT", {f.rule for f in scoring.check_text("a.py", app, "py")})
        capped = app + 'app.config["MAX_CONTENT_LENGTH"] = 1024\n'
        self.assertNotIn("WEB-BODY-LIMIT", {f.rule for f in scoring.check_text("a.py", capped, "py")})


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "proj"
        shutil.copytree(FIXTURES / "weak", self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text: str) -> None:
        (self.root / "foundryguard.toml").write_text(text)

    def test_severity_override_and_off(self):
        self.write('[score.severity]\n"FG-02" = "LOW"\n"WEB-RATE-LIMIT" = "off"\n')
        result, _ = scoring.score_path(self.root)
        sev = {f.signature: f.severity for f in result.findings if f.signature}
        self.assertEqual(sev["FG-02"], "LOW")
        self.assertNotIn("FG-54", sev)
        self.assertTrue(any(n.startswith("config: ") for n in result.notes))

    def test_ignore_and_max_depth(self):
        self.write('[score]\nignore = ["backend/*"]\n')
        result, _ = scoring.score_path(self.root)
        self.assertFalse([f for f in result.findings if f.file.startswith("backend/")])
        self.write("[score]\nmax_depth = 0\n")
        result, _ = scoring.score_path(self.root)
        self.assertEqual(result.files_scanned, 0)
        self.write("[score]\nmax_depth = 1\n")
        result, _ = scoring.score_path(self.root)
        self.assertEqual(result.files_scanned, 2)

    def test_init_writes_config_into_project_root(self):
        (self.root / "foundry.toml").write_text("[profile.default]\n")
        sub = self.root / "src"
        cwd = os.getcwd()
        try:
            os.chdir(sub)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(foundryguard.main(["init"]), 0)
                self.assertEqual(foundryguard.main(["init"]), 1)  # exists, no --force
                self.assertEqual(foundryguard.main(["init", "--force"]), 0)
        finally:
            os.chdir(cwd)
        cfg = self.root / "foundryguard.toml"
        self.assertTrue(cfg.is_file())
        data = compiler._toml(cfg)  # every key is commented out, so it must still parse
        self.assertIn("score", data)
        text = cfg.read_text()
        for key in ("ignore =", "max_depth =", "[score.severity]", "FG-02"):
            self.assertIn(key, text)
        self.assertEqual(scoring.load_scan_config(self.root).severity, {})

    def test_cli_score_with_config(self):
        cfg = Path(self.tmp.name) / "custom.toml"
        cfg.write_text('[score.severity]\n"FG-03" = "off"\n')
        out = Path(self.tmp.name) / "report"
        with contextlib.redirect_stdout(io.StringIO()) as buf, contextlib.redirect_stderr(io.StringIO()):
            rc = foundryguard.main(["score", str(self.root), "--out", str(out), "--config", str(cfg), "--json"])
        self.assertEqual(rc, 0)
        self.assertNotIn("SOL-TX-ORIGIN", buf.getvalue())
        self.assertIn('"signature": "FG-07"', buf.getvalue())


class ReportTests(unittest.TestCase):
    def test_html_lists_the_database_and_fixes(self):
        with tempfile.TemporaryDirectory() as d:
            result, page = scoring.simulate(str(FIXTURES / "weak"), run_forge=False, out_dir=d)
            html = page.read_text()
        self.assertIn("<h2>Signature database</h2>", html)
        rows = dict((sid, hit) for hit, sid in re.findall(r'<tr class="sigrow( hit)?"><td>(FG-\d+)</td>', html))
        self.assertEqual(len(rows), len(signatures.SIGNATURES))
        self.assertTrue(all(rows[sid] for sid, _, _ in EXPECTED_WEAK))
        self.assertIn('<pre class="fix">', html)
        self.assertIn('<span class="sig">FG-07</span>', html)
        self.assertNotRegex(html, r"linear-gradient|animation")


class EntryPointTests(unittest.TestCase):
    def test_console_scripts(self):
        text = (REPO / "pyproject.toml").read_text()
        scripts = dict(re.findall(r'^(foundryguard[\w-]*)\s*=\s*"([^"]+)"', text, re.M))
        self.assertEqual(scripts["foundryguard"], "foundryguard.foundryguard:main")
        self.assertEqual(scripts["foundryguard-gui"], "foundryguard.gui:main")
        version = re.search(r'^version = "([^"]+)"', text, re.M).group(1)
        import parser as fg_parser  # src/cli/parser.py (first on sys.path)
        self.assertEqual(fg_parser.TOOL_VERSION, version)
        with contextlib.redirect_stdout(io.StringIO()) as buf, self.assertRaises(SystemExit):
            foundryguard.main(["--version"])
        self.assertIn(version, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
