"""103-signature database: catalog shape, one sample per signature that must match, a fixed form that must not,
and the report.

Samples live in fixtures/ultrapack/weak (one file or folder per signature, named fgNN_*), their fixed forms in
fixtures/ultrapack/safe. Bridge signatures need a backend and a contract together, so they use the Layer 12
fixture; response-header signatures are checked against a canned set of headers.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import scoring  # noqa: E402
import signatures  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACK = FIXTURES / "ultrapack"
BRIDGE_WEAK = FIXTURES / "bridge" / "weak"
HTTP_SIGS = {"FG-55", "FG-75", "FG-78", "FG-79", "FG-84", "FG-85", "FG-86", "FG-87", "FG-88", "FG-89"}
BRIDGE_SIGS = {"FG-30", "FG-31", "FG-32", "FG-51", "FG-52"} | {f"FG-{n}" for n in range(91, 104)}


def _fg(name: str) -> str:
    return "FG-" + re.match(r"fg(\d+)_", name).group(1)


def _samples(kind: str) -> dict[str, Path]:
    return {_fg(p.name): p for p in sorted((PACK / kind).iterdir())}


WEAK = _samples("weak")
SAFE = _samples("safe")
_cache: dict[Path, set[str]] = {}


def _sigs_in(path: Path) -> set[str]:
    if path not in _cache:
        result, _ = scoring.score_path(path, config=scoring.ScanConfig())
        _cache[path] = {f.signature for f in result.findings if f.signature}
    return _cache[path]


def _http_findings() -> list:
    headers = [("Set-Cookie", "sid=abc; Path=/"), ("Access-Control-Allow-Origin", "*"),
               ("Server", "nginx/1.18.0"), ("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")]
    found = scoring.check_headers("https://shop.example.com/", headers)
    found += scoring.check_headers("http://shop.example.com/", [])
    found += scoring.check_html("index.html", '<img src="http://cdn.example.com/a.png">', "https://shop.example.com/")
    return signatures.apply(found)


class CatalogTests(unittest.TestCase):
    def test_103_signatures_split_50_53(self):
        sigs = signatures.SIGNATURES
        self.assertEqual(len(sigs), 103)
        self.assertEqual([s.id for s in sigs], [f"FG-{i:02d}" for i in range(1, 104)])
        self.assertEqual(sum(s.surface == "web3" for s in sigs), 50)
        self.assertEqual(sum(s.surface == "web2" for s in sigs), 53)
        self.assertTrue(all(s.stack == "solidity" for s in sigs if s.surface == "web3"))
        self.assertFalse([s.id for s in sigs if s.surface == "web2" and s.stack == "solidity"])

    def test_every_rule_name_belongs_to_one_signature(self):
        names = [n for s in signatures.SIGNATURES for n in (s.rule, *s.aliases)]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len({s.title for s in signatures.SIGNATURES}), 103)

    def test_every_signature_is_complete(self):
        for s in signatures.SIGNATURES:
            with self.subTest(sig=s.id):
                self.assertIn(s.severity, signatures.SEVERITIES)
                self.assertRegex(s.ref, r"^(CWE-\d+|SWC-\d+)( / (CWE|SWC)-\d+)?$")
                self.assertTrue(s.title and s.mitigation and s.fix)
                self.assertIn(s.stack, ("solidity", "backend", "http", "deps", "bridge"))

    def test_first_fifteen_keep_their_rules(self):
        # FG-01..FG-08 keep their ids; the seven backend signatures moved from FG-09..15 to FG-51..57.
        old = ["SOL-ZERO-ADDRESS", "SOL-DIV-BEFORE-MUL", "SOL-TX-ORIGIN", "SOL-WEAK-RANDOMNESS", "SOL-UNCHECKED-CALL",
               "SOL-ERC20-UNCHECKED", "SOL-ARBITRARY-FROM", "SOL-UNBOUNDED-LOOP"]
        self.assertEqual([signatures.BY_ID[f"FG-{i:02d}"].rule for i in range(1, 9)], old)
        self.assertEqual([signatures.BY_RULE[r].id for r in ("WEB-SECRET", "WEB-WEAK-RANDOM", "WEB-BODY-LIMIT",
                                                              "WEB-RATE-LIMIT", "WEB-CORS-ANY", "WEB-EVAL", "WEB-COMMAND")],
                         [f"FG-{i}" for i in range(51, 58)])

    def test_every_signature_has_a_sample(self):
        covered = set(WEAK) | HTTP_SIGS | BRIDGE_SIGS
        self.assertEqual(covered, set(signatures.BY_ID))


class SampleTests(unittest.TestCase):
    """One generated test per signature: its sample must produce it."""

    def test_bridge_fixture_covers_bridge_signatures(self):
        got = _sigs_in(BRIDGE_WEAK)
        self.assertTrue(BRIDGE_SIGS <= got, sorted(BRIDGE_SIGS - got))

    def test_http_signatures(self):
        got = {f.signature for f in _http_findings()}
        self.assertTrue(HTTP_SIGS <= got, sorted(HTTP_SIGS - got))

    def test_catalog_severity_is_applied(self):
        for f in _http_findings():
            sig = signatures.BY_ID[f.signature]
            if f.rule == sig.rule and sig.fixed:
                self.assertEqual(f.severity, sig.severity, f.rule)


def _weak_test(fg: str, path: Path):
    def test(self):
        result, _ = scoring.score_path(path, config=scoring.ScanConfig())
        hits = [f for f in result.findings if f.signature == fg]
        self.assertTrue(hits, f"{path.name}: {sorted({f.rule for f in result.findings})}")
        sig = signatures.BY_ID[fg]
        for f in hits:
            self.assertGreaterEqual(f.line, 1)
            self.assertTrue(f.evidence, f.rule)
            self.assertEqual(f.fix, sig.fix)
            if f.rule == sig.rule and sig.fixed:
                self.assertEqual(f.severity, sig.severity)
    return test


def _safe_test(fg: str, path: Path):
    def test(self):
        result, _ = scoring.score_path(path, config=scoring.ScanConfig())
        self.assertEqual([(f.rule, f.location) for f in result.findings if f.signature == fg], [])
    return test


for _fg_id, _path in WEAK.items():
    setattr(SampleTests, f"test_{_fg_id.replace('-', '').lower()}_matches", _weak_test(_fg_id, _path))
for _fg_id, _path in SAFE.items():
    setattr(SampleTests, f"test_{_fg_id.replace('-', '').lower()}_fixed_form_is_clean", _safe_test(_fg_id, _path))


class DetectorEdgeTests(unittest.TestCase):
    def test_nonce_based_ecrecover_is_not_malleable_finding(self):
        src = (FIXTURES / "bridge" / "safe" / "contracts" / "SafeClaim.sol").read_text()
        found, _ = scoring.check_solidity("SafeClaim.sol", src, scoring.ALL_PRESETS)
        self.assertNotIn("SOL-SIG-MALLEABLE", {f.rule for f in found})

    def test_timestamp_equality_skips_same_block_guard(self):
        src = """pragma solidity 0.8.24;
contract S { uint256 lastUpdateTime; uint256 acc;
    function update() external { if (block.timestamp == lastUpdateTime) return; acc += 1; lastUpdateTime = block.timestamp; } }"""
        found, _ = scoring.check_solidity("S.sol", src, scoring.ALL_PRESETS)
        self.assertNotIn("SOL-TIMESTAMP-EQUALITY", {f.rule for f in found})

    def test_downcast_of_timestamp_is_allowed(self):
        src = """pragma solidity 0.8.24;
contract C { uint32 t; function poke() external { t = uint32(block.timestamp); } }"""
        found, _ = scoring.check_solidity("C.sol", src, scoring.ALL_PRESETS)
        self.assertNotIn("SOL-UNSAFE-DOWNCAST", {f.rule for f in found})

    def test_eip1967_slot_strings_are_shared_on_purpose(self):
        src = """pragma solidity 0.8.24;
library A { bytes32 constant IMPL = keccak256("eip1967.proxy.implementation"); }
library B { bytes32 constant IMPLEMENTATION = keccak256("eip1967.proxy.implementation"); }"""
        self.assertEqual(scoring.diamond_slots([("A.sol", src)]), [])

    def test_package_json_range_that_reaches_the_fix_is_not_flagged(self):
        reach = '{"dependencies": {"lodash": "^4.17.15", "axios": "^0.19.0"}}'
        hits = signatures.check_manifest("package.json", reach)
        self.assertEqual([t for _, _, t in hits if "lodash" in t], [])
        self.assertEqual(len([t for _, _, t in hits if "axios" in t]), 1)  # ^0.19 can never reach 0.21.1

    def test_flask_ranges(self):
        self.assertTrue(signatures.check_manifest("requirements.txt", "Flask==2.3.1\n"))
        self.assertFalse(signatures.check_manifest("requirements.txt", "Flask==2.3.2\n"))
        self.assertTrue(signatures.check_manifest("requirements.txt", "flask==2.2.4\n"))

    def test_header_middleware_elsewhere_covers_the_app(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "app.js").write_text((WEAK["FG-83"]).read_text())
            self.assertIn("FG-83", {f.signature for f in scoring.score_path(root, config=scoring.ScanConfig())[0].findings})
            (root / "security.js").write_text('const helmet = require("helmet");\nmodule.exports = helmet();\n')
            self.assertNotIn("FG-83", {f.signature for f in scoring.score_path(root, config=scoring.ScanConfig())[0].findings})

    def test_cookie_calls(self):
        def rules(name, text, lang):
            return [r for r, _, _ in signatures.check_backend(text, lang) if r == "WEB-COOKIE-INSECURE"]
        self.assertEqual(len(rules("a.js", 'res.cookie("sid", v);\n', "js")), 1)
        self.assertEqual(rules("a.js", 'res.cookie("sid", v, { httpOnly: true, secure: true });\n', "js"), [])
        self.assertEqual(len(rules("a.php", '<?php setcookie("sid", $v);\n', "php")), 1)
        self.assertEqual(rules("a.php", '<?php setcookie("sid", $v, ["secure" => true, "httponly" => true]);\n', "php"), [])
        self.assertEqual(rules("c.py", "jar.set_cookie(cookie)\nself.set_cookie(c)\n", "py"), [])

    def test_severity_override_by_new_id(self):
        cfg = {"score": {"severity": {"FG-62": "LOW", "FG-90": "off"}}}
        over = signatures.severity_overrides(cfg)
        self.assertEqual(over["WEB-SSRF"], "LOW")
        self.assertEqual(over["WEB-VULN-DEPENDENCY"], "off")


class ReportTests(unittest.TestCase):
    def test_report_lists_all_103_and_the_matched_ones_with_fixes(self):
        with tempfile.TemporaryDirectory() as d:
            result, page = scoring.simulate(str(PACK / "weak"), run_forge=False, out_dir=d)
            html = page.read_text()
        rows = re.findall(r'<tr class="sigrow( hit)?"><td>(FG-\d\d+)</td>', html)
        self.assertEqual(len(rows), 103)
        self.assertEqual([r[1] for r in rows], [s.id for s in signatures.SIGNATURES])
        self.assertIn("Contract surface, FG-01 to FG-50", html)
        self.assertIn("Web surface, FG-51 to FG-103", html)
        self.assertIn("<h3>Matched</h3>", html)
        for fg in ("FG-10", "FG-24", "FG-62", "FG-90"):
            self.assertIn(f'<span class="sig">{fg}</span>', html)
        self.assertIn("fg62_ssrf.py:7", html)
        self.assertNotRegex(html, r"linear-gradient|animation")
        self.assertLess(result.score, 10)


if __name__ == "__main__":
    unittest.main()
