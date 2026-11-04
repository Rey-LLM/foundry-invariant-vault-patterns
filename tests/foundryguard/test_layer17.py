"""0.17: Layer 17, the threat intelligence sync (intel_sync.py).

No test touches the network: every sync gets a fake fetcher. The OSV sample is a real record
(PYSEC-2021-142, PyYAML full_load) saved from osv.dev.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import foundryguard  # noqa: E402
import intel_sync  # noqa: E402
import scoring  # noqa: E402
import signatures  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "intel"
PACK_FILE = REPO / "intel" / "foundryguard-rules.json"
PACK_BYTES = PACK_FILE.read_bytes()
OSV_PYYAML = (FIXTURES / "osv-pyyaml.json").read_bytes()


def _rule(**over) -> dict:
    d = {"id": "FGX-TEST-1", "severity": "HIGH", "ref": "CWE-94", "langs": ["py"], "title": "t", "mitigation": "m",
         "pattern": r"\bdanger\s*\(", "test": {"hit": "danger(x)", "miss": "safe(x)"}}
    d.update(over)
    return d


def _pack(*rules) -> bytes:
    return json.dumps({"format": "foundryguard-rules/1", "rules": list(rules)}).encode()


def _osv_npm(name: str, introduced: str, fixed: str | None, vid: str = "GHSA-aaaa-bbbb-cccc") -> bytes:
    events = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])
    return json.dumps({"vulns": [{"id": vid, "aliases": ["CVE-2099-0001"], "summary": "test flaw",
                                  "affected": [{"package": {"name": name, "ecosystem": "npm"},
                                                "ranges": [{"type": "SEMVER", "events": events}]}]}]}).encode()


class Fetcher:
    """Serves the default pack and OSV answers; records every call."""

    def __init__(self, pack: bytes = PACK_BYTES, osv: dict[str, bytes] | None = None, fail: bool = False):
        self.pack, self.osv, self.fail, self.calls = pack, osv or {}, fail, []

    def __call__(self, url: str, body: bytes | None = None) -> bytes:
        self.calls.append(url)
        if self.fail:
            raise urllib.error.URLError("offline")
        if url == intel_sync.OSV_QUERY:
            name = json.loads(body)["package"]["name"]
            return self.osv.get(name, b"{}")
        if url == intel_sync.DEFAULT_PACK:
            return self.pack
        raise urllib.error.URLError(f"unexpected {url}")


class IntelCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="foundryguard-l17-"))
        self.cache = self.tmp / "cache" / "intel.json"
        intel_sync.deactivate()

    def tearDown(self) -> None:
        intel_sync.deactivate()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cfg(self, **kw) -> intel_sync.IntelConfig:
        return intel_sync.IntelConfig(**kw)


class PackTests(IntelCase):
    def test_shipped_pack_is_valid_and_every_rule_verifies(self):
        errors: list[str] = []
        rules = intel_sync.parse_pack(PACK_BYTES, "pack", errors)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(rules), 5)
        doc = json.loads(PACK_BYTES)
        for raw, spec in zip(doc["rules"], rules):
            with self.subTest(rule=spec.sig.id):
                self.assertTrue(spec.sig.id.startswith("FGX-"))
                self.assertNotIn(spec.sig.id, signatures.BY_ID)
                self.assertTrue(spec.pattern.search(raw["test"]["hit"]))
                self.assertFalse(spec.pattern.search(raw["test"]["miss"]))

    def test_rejects(self):
        bad = {
            "id": _rule(id="FG-01"),
            "severity": _rule(severity="URGENT"),
            "ref": _rule(ref="see blog post"),
            "langs": _rule(langs=["rust"]),
            "backref": _rule(pattern=r"(a)\1", test={"hit": "aa", "miss": "b"}),
            "nested": _rule(pattern=r"(a+)+b", test={"hit": "ab", "miss": "c"}),
            "long": _rule(pattern="a" * 400),
            "no samples": {k: v for k, v in _rule().items() if k != "test"},
            "hit fails": _rule(test={"hit": "nothing here", "miss": "safe(x)"}),
            "miss matches": _rule(test={"hit": "danger(x)", "miss": "danger(y)"}),
            "bad regex": _rule(pattern="(unclosed"),
        }
        for name, raw in bad.items():
            with self.subTest(case=name), self.assertRaises(intel_sync.IntelError):
                intel_sync.validate_rule(raw, "t")

    def test_bad_rules_are_dropped_good_ones_kept(self):
        errors: list[str] = []
        rules = intel_sync.parse_pack(_pack(_rule(), _rule(id="FGX-BAD", pattern=r"(x+)*")), "t", errors)
        self.assertEqual([r.sig.id for r in rules], ["FGX-TEST-1"])
        self.assertEqual(len(errors), 1)

    def test_not_a_pack(self):
        for data in (b"<html>", b"[]", json.dumps({"format": "other", "rules": []}).encode()):
            with self.assertRaises(intel_sync.IntelError):
                intel_sync.parse_pack(data, "t", [])


class OsvTests(IntelCase):
    def test_real_osv_record(self):
        advs = intel_sync.osv_advisories(json.loads(OSV_PYYAML), "pypi")
        self.assertEqual([(a.package, a.introduced, a.fixed, a.id) for a in advs], [("pyyaml", None, "5.4", "CVE-2020-14343")])

    def test_other_ecosystem_and_withdrawn_are_skipped(self):
        self.assertEqual(intel_sync.osv_advisories(json.loads(OSV_PYYAML), "npm"), [])
        doc = json.loads(_osv_npm("left-pad", "0", "1.0.0"))
        doc["vulns"][0]["withdrawn"] = "2024-01-01T00:00:00Z"
        self.assertEqual(intel_sync.osv_advisories(doc, "npm"), [])

    def test_open_range_and_last_affected(self):
        advs = intel_sync.osv_advisories(json.loads(_osv_npm("left-pad", "2.0.0", None)), "npm")
        self.assertEqual([(a.introduced, a.fixed) for a in advs], [("2.0.0", None)])
        doc = {"vulns": [{"id": "GHSA-x", "affected": [{"package": {"name": "p", "ecosystem": "npm"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.2.3"}]}]}]}]}
        self.assertEqual(intel_sync.osv_advisories(doc, "npm"), [])

    def test_malformed_records_do_not_raise(self):
        for doc in ({"vulns": [None, 3, {"affected": [{"ranges": "x"}]}]}, {"vulns": "x"}, [], "x"):
            self.assertEqual(intel_sync.osv_advisories(doc, "npm"), [])


class SyncTests(IntelCase):
    def test_network_sync_activates_and_caches(self):
        fetch = Fetcher(osv={"pyyaml": OSV_PYYAML, "left-pad": _osv_npm("left-pad", "0", "1.3.0")})
        cfg = self.cfg(packages={"npm": ("left-pad",)})
        res = intel_sync.sync(cfg, fetch, self.cache)
        self.assertEqual(res.source, "network")
        self.assertGreaterEqual(len(res.rules), 5)
        self.assertEqual(len(res.advisories), 2)
        self.assertEqual(res.label(), f"Signatures: 150 hardcoded + {res.dynamic} dynamic verified")
        self.assertIs(intel_sync.status(), res)
        self.assertTrue(self.cache.is_file())
        self.assertEqual(len(signatures.DYNAMIC_RULES), len(res.rules))
        # the built-in catalog is untouched
        self.assertEqual(len(signatures.SIGNATURES), 150)
        self.assertNotIn("FGX-SWC-129", signatures.BY_ID)

    def test_offline_falls_back_to_cache_then_to_builtin(self):
        intel_sync.sync(self.cfg(), Fetcher(), self.cache)
        res = intel_sync.sync(self.cfg(), Fetcher(fail=True), self.cache, force=True)
        self.assertEqual(res.source, "cache")
        self.assertGreaterEqual(len(res.rules), 5)
        self.assertTrue(res.label().endswith("(cached)"))
        self.cache.unlink()
        res = intel_sync.sync(self.cfg(), Fetcher(fail=True), self.cache, force=True)
        self.assertEqual(res.source, "none")
        self.assertEqual(signatures.DYNAMIC_RULES, ())
        self.assertIn("no cache", res.label())

    def test_offline_osv_stops_after_first_failure(self):
        fetch = Fetcher(fail=True)
        intel_sync.sync(self.cfg(), fetch, self.cache)
        self.assertEqual(fetch.calls.count(intel_sync.OSV_QUERY), 1)

    def test_fresh_cache_skips_the_network(self):
        intel_sync.sync(self.cfg(), Fetcher(), self.cache, now=1000.0)
        fetch = Fetcher()
        res = intel_sync.sync(self.cfg(), fetch, self.cache, now=1000.0 + 3600)
        self.assertEqual(fetch.calls, [])
        self.assertEqual(res.source, "cache")
        res = intel_sync.sync(self.cfg(), fetch, self.cache, now=1000.0 + 25 * 3600)
        self.assertEqual(res.source, "network")

    def test_tampered_cache_is_revalidated(self):
        intel_sync.sync(self.cfg(), Fetcher(), self.cache)
        doc = json.loads(self.cache.read_text())
        doc["rules"][0]["pattern"] = r"(a+)+$"
        doc["advisories"] = [{"eco": "npm", "package": "x", "introduced": None, "fixed": None, "id": "GHSA-1"}]
        self.cache.write_text(json.dumps(doc))
        res = intel_sync.load_cache(self.cache)
        self.assertEqual(len(res.rules), len(doc["rules"]) - 1)
        self.assertEqual(res.advisories, [])
        self.assertEqual(len(res.errors), 2)

    def test_disabled(self):
        fetch = Fetcher()
        res = intel_sync.sync(self.cfg(enabled=False), fetch, self.cache)
        self.assertEqual((res.source, fetch.calls), ("off", []))
        self.assertTrue(res.label().endswith("(sync off)"))

    def test_url_rules_and_pins(self):
        with self.assertRaises(intel_sync.IntelError):
            intel_sync.check_url("http://raw.githubusercontent.com/x.json", intel_sync.DEFAULT_HOSTS)
        with self.assertRaises(intel_sync.IntelError):
            intel_sync.check_url("https://evil.example/x.json", intel_sync.DEFAULT_HOSTS)
        cfg = self.cfg(osv=False, pins={intel_sync.DEFAULT_PACK: "0" * 64})
        res = intel_sync.sync(cfg, Fetcher(), self.cache)
        self.assertEqual(res.source, "none")
        self.assertTrue(any("SHA-256" in e for e in res.errors))
        cfg = self.cfg(osv=False, pins={intel_sync.DEFAULT_PACK: hashlib.sha256(PACK_BYTES).hexdigest()})
        self.assertEqual(intel_sync.sync(cfg, Fetcher(), self.cache).source, "network")

    def test_feed_hosts_from_config_are_allowed(self):
        cfg = intel_sync.IntelConfig.from_dict({"intel": {"feeds": ["https://rules.example.org/p.json"]}})
        self.assertIn("rules.example.org", cfg.hosts)
        self.assertEqual(cfg.feeds[0], intel_sync.DEFAULT_PACK)

    def test_background_sync_does_not_block(self):
        gate = threading.Event()
        inner = Fetcher()

        def slow(url, body=None):
            gate.wait(5)
            return inner(url, body)

        t0 = time.monotonic()
        job = intel_sync.BackgroundSync(self.cfg(osv=False), slow, self.cache).start()
        self.assertLess(time.monotonic() - t0, 0.5)
        self.assertIsNone(job.poll())
        gate.set()
        job.thread.join(5)
        self.assertEqual(job.poll().source, "network")

    def test_background_sync_survives_a_crashing_fetcher(self):
        def boom(url, body=None):
            raise RuntimeError("bug")

        job = intel_sync.BackgroundSync(self.cfg(osv=False), boom, self.cache).start()
        job.thread.join(5)
        self.assertIn(job.poll().source, ("none", "cache"))


class ConfigTests(IntelCase):
    def test_toggle_locations(self):
        self.assertFalse(intel_sync.IntelConfig.from_dict({"intel": {"auto_update_signatures": False}}).enabled)
        self.assertFalse(intel_sync.IntelConfig.from_dict({"auto_update_signatures": False}).enabled)
        self.assertTrue(intel_sync.IntelConfig.from_dict({}).enabled)
        self.assertFalse(intel_sync.IntelConfig.from_dict({}, default_enabled=False).enabled)

    def test_unknown_ecosystem(self):
        with self.assertRaises(ValueError):
            intel_sync.IntelConfig.from_dict({"intel": {"packages": {"cargo": ["serde"]}}})

    def test_init_template_turns_sync_on(self):
        path = self.tmp / "foundryguard.toml"
        path.write_text(foundryguard.CONFIG_TEMPLATE)
        import compiler
        cfg = compiler._toml(path)
        self.assertIs(cfg["intel"]["auto_update_signatures"], True)
        self.assertTrue(intel_sync.IntelConfig.from_dict(cfg).enabled)

    def test_watchlist_extends_builtin(self):
        cfg = intel_sync.IntelConfig.from_dict({"intel": {"packages": {"npm": ["next", "lodash"]}}})
        wl = cfg.watchlist()
        self.assertIn("lodash", wl["npm"])
        self.assertEqual(wl["npm"].count("lodash"), 1)
        self.assertEqual(wl["npm"][-1], "next")
        self.assertIn("pyyaml", wl["pypi"])


class ScanTests(IntelCase):
    def setUp(self) -> None:
        super().setUp()
        self.proj = self.tmp / "proj"
        (self.proj / "src").mkdir(parents=True)
        (self.proj / "src" / "Typo.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ncontract Typo {\n"
            "    mapping(address => uint256) public balances;\n    string private password;\n"
            "    function add(uint256 amount) external {\n        balances[msg.sender] =+ amount;\n    }\n}\n")
        (self.proj / "unpack.py").write_text("import tarfile\n\ndef unpack(p, d):\n"
                                             "    with tarfile.open(p) as t:\n        t.extractall(d)\n")
        (self.proj / "requirements.txt").write_text("left-pad-py==1.0.0\n")

    def rules(self) -> dict[str, list]:
        result, _ = scoring.score_path(self.proj)
        out: dict[str, list] = {}
        for f in result.findings:
            out.setdefault(f.signature or f.rule, []).append(f)
        return out

    def test_dynamic_rules_only_while_active(self):
        before = self.rules()
        self.assertFalse(any(k.startswith("FGX-") for k in before))
        osv = {"left-pad-py": json.dumps({"vulns": [{"id": "PYSEC-2099-1", "summary": "test", "affected": [
            {"package": {"name": "left-pad-py", "ecosystem": "PyPI"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}]}]}).encode()}
        intel_sync.sync(self.cfg(packages={"pypi": ("left-pad-py",)}), Fetcher(osv=osv), self.cache)
        got = self.rules()
        typo = got["FGX-SWC-129"][0]
        self.assertEqual((typo.file, typo.line, typo.layer, typo.severity), ("src/Typo.sol", 7, "L17", "MEDIUM"))
        self.assertEqual(got["FGX-SWC-136"][0].line, 5)
        self.assertEqual((got["FGX-CVE-2007-4559"][0].file, got["FGX-CVE-2007-4559"][0].line), ("unpack.py", 5))
        dep = [f for f in got["FG-90"] if "left-pad-py" in f.title]
        self.assertTrue(dep and "PYSEC-2099-1" in dep[0].title and "fixed in 1.1" in dep[0].title)
        intel_sync.deactivate()
        self.assertEqual(set(self.rules()), set(before))

    def test_override_dynamic_by_id(self):
        intel_sync.sync(self.cfg(osv=False), Fetcher(), self.cache)
        (self.proj / "foundryguard.toml").write_text('[score.severity]\n"FGX-SWC-129" = "off"\n')
        got = self.rules()
        self.assertNotIn("FGX-SWC-129", got)
        self.assertIn("FGX-SWC-136", got)

    def test_bidi_rule_reads_raw_lines(self):
        intel_sync.sync(self.cfg(osv=False), Fetcher(), self.cache)
        (self.proj / "src" / "Trojan.sol").write_text(
            "pragma solidity ^0.8.24;\ncontract T {\n    // \u202e } if (isAdmin) { \u2066\n}\n", encoding="utf-8")
        hits = [f for f in self.rules().get("FGX-SWC-130", []) if f.file == "src/Trojan.sol"]
        self.assertEqual([f.line for f in hits], [3])

    def test_report_lists_dynamic_hits(self):
        intel_sync.sync(self.cfg(osv=False), Fetcher(), self.cache)
        result, _ = scoring.score_path(self.proj)
        html = "".join(scoring.signature_section(result.findings))
        self.assertIn("Dynamic signatures", html)
        self.assertIn("FGX-SWC-129", html)

    def test_dynamic_npm_advisory_in_package_json(self):
        (self.proj / "package.json").write_text(json.dumps({"dependencies": {"tiny-lib": "^1.2.0"}}, indent=2))
        intel_sync.sync(self.cfg(packages={"npm": ("tiny-lib",)}),
                        Fetcher(osv={"tiny-lib": _osv_npm("tiny-lib", "1.0.0", "2.0.0")}), self.cache)
        dep = [f for f in self.rules()["FG-90"] if "tiny-lib" in f.title]
        self.assertEqual(len(dep), 1)
        self.assertIn("cannot reach 2.0.0", dep[0].title)

    def test_score_uses_cache_only_when_toml_enables_it(self):
        intel_sync.sync(self.cfg(osv=False), Fetcher(), self.cache)
        intel_sync.deactivate()
        env = {"FOUNDRYGUARD_INTEL_CACHE": str(self.cache)}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            self.assertIsNone(intel_sync.use_cache_if_enabled(self.proj))
            self.assertEqual(signatures.DYNAMIC_RULES, ())
            (self.proj / "foundryguard.toml").write_text("[intel]\nauto_update_signatures = true\n")
            res = intel_sync.use_cache_if_enabled(self.proj)
            self.assertEqual(res.source, "cache")
            self.assertTrue(signatures.DYNAMIC_RULES)
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class CliTests(IntelCase):
    def test_intel_status(self):
        intel_sync.sync(self.cfg(osv=False), Fetcher(), self.cache)
        old = os.environ.get("FOUNDRYGUARD_INTEL_CACHE")
        os.environ["FOUNDRYGUARD_INTEL_CACHE"] = str(self.cache)
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = foundryguard.main(["intel", "status", "--json"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["source"], "cache")
            self.assertIn("FGX-SWC-129", [r["id"] for r in out["rules"]])
        finally:
            os.environ.pop("FOUNDRYGUARD_INTEL_CACHE") if old is None else os.environ.__setitem__(
                "FOUNDRYGUARD_INTEL_CACHE", old)


@unittest.skipUnless(os.environ.get("DISPLAY") or sys.platform in ("darwin", "win32"), "no display")
class GuiIntelTests(IntelCase):
    def test_label_updates_after_background_sync(self):
        import gui
        try:
            root = gui.make_root()
        except Exception:
            self.skipTest("Tk not available")
        try:
            app = gui.App(root, "")
            self.assertEqual(app.intel_var.get(), "Signatures: 150 hardcoded")
            app.start_intel_sync(self.cfg(osv=False), Fetcher(), self.cache)
            deadline = time.time() + 10
            while "dynamic verified" not in app.intel_var.get() and time.time() < deadline:
                root.update()
                time.sleep(0.02)
            self.assertRegex(app.intel_var.get(), r"^Signatures: 150 hardcoded \+ \d+ dynamic verified$")
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
