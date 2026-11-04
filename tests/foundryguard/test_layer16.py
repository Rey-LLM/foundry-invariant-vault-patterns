"""0.16: FG-104..FG-150 and the engine changes that came with them.

The per-signature samples (fixtures/ultrapack/{weak,safe}/fg104..fg150) are picked up by test_layer15, which
builds one match test and one clean test per file. This module covers what those cannot: the new detectors'
edge cases, the literal-hint pool behind the line rules, the compiled comment stripper, the scandir walk, the
bounded reader, and the plain-text findings log the desktop window prints.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import parser as fg_parser  # noqa: E402
import scoring  # noqa: E402
import signatures  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PACK = FIXTURES / "ultrapack"


def _sol_rules(src: str) -> set[str]:
    found, _ = scoring.check_solidity("S.sol", src, scoring.ALL_PRESETS)
    return {f.rule for f in found}


def _web_rules(src: str, lang: str) -> set[str]:
    return {f.rule for f in scoring.check_text("a." + lang, src, lang)}


class CatalogTests(unittest.TestCase):
    def test_new_ids_are_appended_and_old_ids_keep_their_rules(self):
        self.assertEqual(signatures.BY_ID["FG-103"].rule, "BRIDGE-DEADLINE-UNENFORCED")
        self.assertEqual(signatures.BY_ID["FG-50"].rule, "SOL-UNFUNDED-REWARDS")
        self.assertEqual(signatures.BY_ID["FG-104"].rule, "SOL-STAKE-NO-LOCK")
        self.assertEqual(signatures.BY_ID["FG-150"].rule, "WEB-WS-PLAINTEXT")

    def test_every_new_rule_has_a_detector_layer(self):
        for n in range(104, 151):
            sig = signatures.BY_ID[f"FG-{n}"]
            with self.subTest(sig=sig.id):
                if sig.stack == "solidity":
                    self.assertIn(sig.rule, scoring._SIG_LAYER)
                else:
                    in_line = any(r.rule == sig.rule for r in scoring.LINE_RULES)
                    self.assertTrue(in_line or sig.rule in scoring.FILE_RULE_LAYER, sig.rule)

    def test_override_by_new_id(self):
        over = signatures.severity_overrides({"score": {"severity": {"FG-147": "off", "FG-111": "HIGH"}}})
        self.assertEqual(over["WEB-API-STATE-NO-AUTH"], "off")
        self.assertEqual(over["SOL-TIMELOCK-BYPASS"], "HIGH")


class SolidityEdgeTests(unittest.TestCase):
    def test_reentrancy_flag_is_not_a_lock_period(self):
        src = """pragma solidity 0.8.24;
contract V { uint256 private locked = 1; mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 a) external { require(locked == 1); balances[msg.sender] -= a; } }"""
        self.assertNotIn("SOL-STAKE-NO-LOCK", _sol_rules(src))

    def test_lengths_checked_by_a_hash_over_both_arrays(self):
        src = """pragma solidity 0.8.24;
contract G { mapping(uint256 => bool) done;
    function execute(address[] calldata targets, bytes[] calldata datas) external {
        uint256 id = uint256(keccak256(abi.encode(targets, datas)));
        require(!done[id]); done[id] = true;
        for (uint256 i = 0; i < targets.length; ++i) { (bool ok, ) = targets[i].call(datas[i]); require(ok); } } }"""
        self.assertNotIn("SOL-ARRAY-LENGTH-MISMATCH", _sol_rules(src))

    def test_wrapper_burn_proves_ownership(self):
        src = """pragma solidity 0.8.24;
interface INFT { function safeTransferFrom(address, address, uint256) external; }
contract W { INFT nft; mapping(uint256 => address) public holder;
    function _burn(uint256 id) internal { delete holder[id]; }
    function withdrawTo(address account, uint256 tokenId) external {
        _burn(tokenId);
        nft.safeTransferFrom(address(this), account, tokenId); } }"""
        self.assertNotIn("SOL-NFT-UNSTAKE-ANY", _sol_rules(src))

    def test_fee_setter_inside_a_timelocked_contract(self):
        src = """pragma solidity 0.8.24;
contract F { address owner; uint256 fee; uint256 pendingFee; uint256 eta;
    function setFee(uint256 f) external { require(msg.sender == owner); pendingFee = f; eta = block.timestamp + 2 days; } }"""
        self.assertNotIn("SOL-NO-TIMELOCK", _sol_rules(src))

    def test_scaled_reward_per_token_view(self):
        src = """pragma solidity 0.8.24;
contract R { uint256 public rewardPerTokenStored; uint256 rate; uint256 last; uint256 total;
    function rewardPerToken() public view returns (uint256) {
        return rewardPerTokenStored + (block.timestamp - last) * rate * 1e18 / total; } }"""
        self.assertNotIn("SOL-REWARD-PRECISION", _sol_rules(src))

    def test_erc20_safe_transfer_from_is_not_a_receiver_hook(self):
        src = """pragma solidity 0.8.24;
interface IERC20 { function safeTransferFrom(address, address, uint256) external; }
contract P { IERC20 token; uint256 total;
    function deposit(uint256 a) external { token.safeTransferFrom(msg.sender, address(this), a); total += a; } }"""
        self.assertNotIn("SOL-NFT-HOOK-REENTRANCY", _sol_rules(src))


class WebEdgeTests(unittest.TestCase):
    def test_auth_routes_are_not_state_routes_without_auth(self):
        src = 'const router = require("express").Router();\nrouter.post("/login", handler);\n'
        self.assertNotIn("WEB-API-STATE-NO-AUTH", _web_rules(src, "js"))

    def test_jwt_expiry_set_in_payload(self):
        src = 'import jwt, time\n\ndef t(u):\n    return jwt.encode({"sub": u, "exp": time.time() + 900}, KEY)\n'
        self.assertNotIn("WEB-JWT-NO-EXPIRY", _web_rules(src, "py"))

    def test_flask_session_with_config_object(self):
        src = 'from flask import Flask, session\napp = Flask(__name__)\napp.config.from_object("settings")\n'
        self.assertNotIn("WEB-SESSION-COOKIE-CONFIG", _web_rules(src, "py"))

    def test_url_in_template_literal_no_longer_hides_the_line(self):
        # `//` inside a backtick template used to be read as a comment start, blanking the rest of the line.
        src = 'function f(req) { const link = `https://${req.headers.host}/reset?t=${t}`; send(link); }\n'
        self.assertIn("WEB-HOST-HEADER-LINK", _web_rules(src, "js"))

    def test_local_websocket_is_fine(self):
        self.assertNotIn("WEB-WS-PLAINTEXT", _web_rules('new WebSocket("ws://localhost:8080");\n', "js"))


class LineHintTests(unittest.TestCase):
    """Every line a rule matches must contain one of its hints, or the hint pool would hide real hits."""

    def test_hints_cover_every_fixture_hit(self):
        files = [p for p in FIXTURES.rglob("*") if p.is_file() and scoring._lang(p.name) in ("py", "js", "php", "html")
                 and "node_modules" not in p.parts]
        self.assertGreater(len(files), 100)
        checked = 0
        for p in files:
            for ln in p.read_text(errors="replace").splitlines():
                low = ln.lower()
                for rule in scoring.LINE_RULES:
                    hints = scoring.LINE_HINTS.get(rule.rule)
                    if hints and rule.pattern.search(ln):
                        checked += 1
                        self.assertTrue(any(h in low for h in hints), f"{rule.rule} matched without a hint: {ln!r}")
        self.assertGreater(checked, 100)

    def test_every_rule_has_hints(self):
        self.assertEqual({r.rule for r in scoring.LINE_RULES} - set(scoring.LINE_HINTS), set())
        self.assertTrue(all(h == h.lower() for hs in scoring.LINE_HINTS.values() for h in hs))


class StripCommentsTests(unittest.TestCase):
    def test_offsets_and_newlines_are_kept(self):
        src = 'a = "x // y"; // gone\n/* one\n two */ b = \'q\';\n'
        out = scoring.strip_comments(src)
        self.assertEqual(len(out), len(src))
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertEqual(out.splitlines()[0], 'a = "' + " " * 6 + '"; ' + " " * len("// gone"))
        self.assertEqual(scoring.strip_comments(src, blank_strings=False).splitlines()[0],
                         'a = "x // y"; ' + " " * len("// gone"))
        self.assertIn("b = ' ';", out)

    def test_escapes_and_unterminated(self):
        self.assertEqual(scoring.strip_comments('"a\\"b" x'), '"    " x')
        self.assertEqual(scoring.strip_comments('"open\nnext // c'), '"    \nnext     ')

    def test_templates_only_when_asked(self):
        src = "x = `http://a`; // c\n"
        self.assertEqual(scoring.strip_comments(src, blank_strings=False), "x = `http:" + " " * len("//a`; // c") + "\n")
        self.assertEqual(scoring.strip_comments(src, blank_strings=False, templates=True), "x = `http://a`;     \n")


class WalkAndReadTests(unittest.TestCase):
    def test_discover_order_depth_ignore_and_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel in ("b.sol", "a.py", "sub/c.js", "sub/deep/d.sol", "node_modules/x.js", ".git/y.py",
                        "sub/e.test.js", "sub/f.min.js", "package.json", "notes.txt"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("x\n")
            os.symlink(root / "sub", root / "zlink")
            got = [p.relative_to(root).as_posix() for p in scoring.discover(root, scoring.ScanConfig())]
            self.assertEqual(got, ["a.py", "b.sol", "package.json", "sub/c.js", "sub/deep/d.sol"])
            cfg = scoring.ScanConfig.from_dict({"score": {"max_depth": 1, "ignore": ["a.py"]}})
            got = [p.relative_to(root).as_posix() for p in scoring.discover(root, cfg)]
            self.assertEqual(got, ["b.sol", "package.json", "sub/c.js"])

    def test_bounded_read_matches_text_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "w.js"
            p.write_bytes(b"a\r\nb\rc\n\xff")
            self.assertEqual(scoring.read_source(p), p.read_text(encoding="utf-8", errors="replace"))
            self.assertIsNone(scoring.read_source(p, limit=3))
            notes: list[str] = []
            self.assertEqual(list(scoring.iter_sources([p, Path(d) / "missing.js"], notes, limit=3)), [])
            self.assertEqual(len(notes), 2)

    def test_parser_walk_finds_the_same_sources(self):
        root = FIXTURES / "libs" / "node_modules" / "@openzeppelin" / "contracts"
        if not root.is_dir():
            self.skipTest("fixtures/libs not installed (npm install --prefix tests/foundryguard/fixtures/libs)")
        expected = set()
        for here, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x not in fg_parser.EXCLUDED_DIRS]
            expected |= {(Path(here) / n).resolve() for n in names if n.endswith(".sol")
                         and not n.endswith((".t.sol", ".s.sol"))}
        self.assertEqual(set(fg_parser.discover_sources(root, ["."])), expected)

    def test_classification_cache_keeps_first_match(self):
        rules = fg_parser.build_rules({"classify": {"ignore": ["withdrawFee"], "deposit": ["join"]}})
        self.assertEqual(fg_parser._match_name(rules, "withdrawFee"), ("__ignore__", ""))
        self.assertEqual(fg_parser._match_name(rules, "join"), ("deposit", "in"))
        self.assertEqual(fg_parser._match_name(rules, "unstake"), ("stake_lock", "out"))
        self.assertIsNone(fg_parser._match_name(rules, "name"))


class DigestTests(unittest.TestCase):
    def test_digest_lists_line_severity_and_fix(self):
        result, _ = scoring.score_path(PACK / "weak" / "fg120_reward_claim_no_reset.sol", config=scoring.ScanConfig())
        lines = scoring.finding_digest(result)
        self.assertTrue(lines[0].startswith(f"FoundryGuard {result.score}/100"))
        head = next(i for i, ln in enumerate(lines) if "FG-120" in ln)
        self.assertRegex(lines[head], r"^\[CRITICAL\] FG-120 SOL-REWARD-CLAIM-NO-RESET fg120_reward_claim_no_reset\.sol:\d+ \(-25\)$")
        self.assertIn("  fix:", lines[head:head + 6])
        self.assertIn("    rewards[msg.sender] = 0;", lines)

    def test_digest_limit_and_order(self):
        result, _ = scoring.score_path(PACK / "weak", config=scoring.ScanConfig())
        lines = scoring.finding_digest(result, limit=5)
        heads = [ln for ln in lines if re.match(r"^\[(CRITICAL|HIGH|MEDIUM|LOW)\]", ln)]
        self.assertEqual(len(heads), 5)
        self.assertTrue(all(h.startswith("[CRITICAL]") for h in heads))
        self.assertTrue(lines[-1].startswith("... and "))


if __name__ == "__main__":
    unittest.main()
