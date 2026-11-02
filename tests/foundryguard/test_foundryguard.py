"""FoundryGuard unit tests. Run with `python3 -m unittest discover -s tests/foundryguard -v` or pytest."""

from __future__ import annotations

import contextlib
import io
import json
import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import foundryguard  # noqa: E402
import injector  # noqa: E402
import parser as fg_parser  # noqa: E402
import reporting  # noqa: E402

logging.disable(logging.CRITICAL)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "project"
AST_OUTPUT = Path(__file__).resolve().parent / "fixtures" / "ast" / "solc-output.json"


def contracts(blueprint: dict) -> dict[str, dict]:
    return {c["name"]: c for c in blueprint["contracts"] if not c["external"]}


class ProjectCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="foundryguard-"))
        self.root = self.tmp / "project"
        shutil.copytree(FIXTURE, self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, backend: str = "regex", config: dict | None = None) -> dict:
        return fg_parser.build_blueprint(self.root, [], backend=backend, config=config, run_build=False)

    def gen(self, blueprint: dict, config: dict | None = None, **kw) -> list[dict]:
        out = self.root / "test" / "foundryguard"
        return injector.inject(blueprint, self.root, out, kw.get("only"), 4, "1e24",
                               kw.get("force", False), kw.get("dry_run", False), config)

    def read(self, contract: str, file: str) -> str:
        return (self.root / "test" / "foundryguard" / contract / file).read_text()


class ParserTests(ProjectCase):
    def test_classifies_value_flows(self):
        cs = contracts(self.scan())
        self.assertEqual(cs["SimpleVault"]["categories"], {"deposit": ["deposit(uint256)"], "withdraw": ["withdraw(uint256)"]})
        self.assertEqual(cs["RewardStaking"]["categories"]["stake_lock"], ["stake(uint256)", "unstake(uint256)", "getReward()"])
        self.assertNotIn("deposit", cs["RewardStaking"]["categories"])  # notifyRewardAmount is not a flow
        self.assertEqual(cs["SimpleVault"]["constructor"]["params"][0]["type"], "IERC20")

    def test_public_state_vars_recorded(self):
        cs = contracts(self.scan())
        names = {v["name"]: v["type"] for v in cs["RewardStaking"]["state_vars"]}
        self.assertEqual(names["stakingToken"], "IERC20")
        self.assertIn("totalStaked", cs["RewardStaking"]["accounting_getters"])

    def test_config_classify_rules(self):
        cfg = {"classify": {"reward": ["getReward"], "ignore": ["unstake"]}}
        cs = contracts(self.scan(config=cfg))
        flows = {fn["name"]: (fn["category"], fn["direction"]) for fn in cs["RewardStaking"]["functions"] if fn["category"]}
        self.assertNotIn("unstake", flows)
        self.assertEqual(flows["getReward"], ("stake_lock", "reward"))

    def test_ast_backend_matches_regex(self):
        shutil.copy(AST_OUTPUT, self.root / "solc-output.json")
        ast = contracts(fg_parser.build_blueprint(self.root, [], backend="ast", build_dir="solc-output.json", run_build=False))
        rgx = contracts(self.scan())
        rgx.pop("OZVault")  # not part of the committed AST fixture
        self.assertEqual(sorted(ast), sorted(rgx))
        for name in ast:
            for key in ("kind", "inherits", "categories", "accounting_getters", "pragma", "line"):
                self.assertEqual(ast[name][key], rgx[name][key], f"{name}.{key}")
            self.assertEqual(sorted(f["signature"] for f in ast[name]["functions"]),
                             sorted(f["signature"] for f in rgx[name]["functions"]), name)

    def test_ast_required_but_missing(self):
        with self.assertRaises(SystemExit):
            fg_parser.build_blueprint(self.root, [], backend="ast", build_dir="nowhere", run_build=False)

    def test_load_config(self):
        (self.root / "foundryguard.toml").write_text('[generate]\nactors = 3\n')
        self.assertEqual(fg_parser.load_config(self.root)["generate"]["actors"], 3)
        self.assertEqual(fg_parser.load_config(self.tmp), {})


class InjectorTests(ProjectCase):
    def test_targets_and_skips(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        self.assertNotIn("Token", report, "plain ERC-20 faucet must not be a target")
        self.assertIn("SimpleVault", report)
        self.assertTrue(any("parent contract 'ERC4626'" in w for w in report["OZVault"]["warnings"])
                        if "OZVault" in report else True)
        staking = report["RewardStaking"]
        self.assertFalse(any("notifyRewardAmount" in f for f in staking["flows"]))
        self.assertTrue((self.root / "test" / "foundryguard" / injector.SUPPORT_FILE).is_file())

    def test_token_setup(self):
        self.gen(self.scan())
        test = self.read("SimpleVault", "Invariant.t.sol")
        self.assertIn('token = new FoundryGuardMockERC20("FoundryGuard token"', test)
        self.assertIn("address(token) /* IERC20 token_ */", test)
        self.assertIn("handler = new SimpleVaultGuardHandler(target, tokens, rewardTokens);", test)
        self.assertIn("invariant_tokenSolvency", test)
        handler = self.read("SimpleVault", "Handler.sol")
        self.assertIn("approve(address(_target), type(uint256).max)", handler)
        self.assertIn("uint256 amount_max = target.balanceOf(actor);", handler)

    def test_rewards_funded_and_bounded(self):
        self.gen(self.scan())
        test = self.read("RewardStaking", "Invariant.t.sol")
        self.assertIn("try target.notifyRewardAmount(REWARD_BUDGET)", test)
        self.assertIn("invariant_rewardsBoundedByFunding_rewardToken", test)
        self.assertIn("_recordRewards(actor, rewardBefore_);", self.read("RewardStaking", "Handler.sol"))

    def test_upgradeable_behind_proxy(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        self.assertTrue(report["UpgradeableVault"]["upgradeable"])
        test = self.read("UpgradeableVault", "Invariant.t.sol")
        self.assertIn("new FoundryGuardERC1967Proxy(", test)
        self.assertIn("UpgradeableVault.initialize.selector", test)
        handler = self.read("UpgradeableVault", "Handler.sol")
        # the owner_ argument of withdraw must be the pranked actor
        self.assertIn("try target.withdraw(amount_, _actor(receiverSeed), actor)", handler)

    def test_erc4626_presets(self):
        vault = {
            "name": "V", "kind": "contract", "file": "src/V.sol", "line": 1, "pragma": "^0.8.20", "inherits": [],
            "external": False, "test_helper": False, "deployable": True, "accounting_getters": ["totalSupply", "balanceOf"],
            "state_vars": [], "categories": {},
            "constructor": {"params": [{"type": "IERC20", "name": "asset_", "location": None}], "mutability": "nonpayable"},
            "functions": [],
        }

        def fn(name, params, category=None, direction=None, amount=None, unit=None, mut="nonpayable", ret=1):
            ps = [{"type": t, "name": n, "location": None} for t, n in params]
            return {"name": name, "kind": "function", "signature": f"{name}({','.join(t for t, _ in params)})",
                    "params": ps, "returns": [{"type": "uint256", "name": "", "location": None}] * ret,
                    "visibility": "public", "mutability": mut, "modifiers": [], "category": category,
                    "direction": direction, "amount_param": amount, "unit": unit}

        vault["functions"] = [
            fn("asset", [], mut="view"), fn("totalAssets", [], mut="view"), fn("totalSupply", [], mut="view"),
            fn("balanceOf", [("address", "a")], mut="view"), fn("convertToAssets", [("uint256", "s")], mut="view"),
            fn("previewDeposit", [("uint256", "a")], mut="view"), fn("previewRedeem", [("uint256", "s")], mut="view"),
            fn("maxRedeem", [("address", "o")], mut="view"),
            fn("deposit", [("uint256", "assets"), ("address", "receiver")], "deposit", "in", "assets", "assets"),
            fn("redeem", [("uint256", "shares"), ("address", "receiver"), ("address", "owner")], "withdraw", "out", "shares", "shares"),
            fn("approve", [("address", "s"), ("uint256", "a")], ret=1), fn("transfer", [("address", "t"), ("uint256", "a")]),
        ]
        bp = {"schema": injector.SUPPORTED_SCHEMA, "contracts": [vault]}
        report = self.gen(bp)
        names = report[0]["invariants"]
        for inv in ("invariant_erc4626_previewsHonoured", "invariant_erc4626_depositAlwaysMintsShares",
                    "invariant_erc4626_solvency", "invariant_erc4626_sharesBackedByAssets",
                    "invariant_erc4626_assetsOutBoundedByIn", "invariant_erc4626_sharesOutBoundedByIn"):
            self.assertIn(inv, names)
        handler = self.read("V", "Handler.sol")
        self.assertIn("uint256 shares_max = target.maxRedeem(actor);", handler)
        self.assertIn("if (previewOk_ && !(result_ >= preview_)) ghost_previewViolations++;", handler)

    def test_admin_only_not_fuzzed(self):
        bp = self.scan()
        for c in bp["contracts"]:
            if c["name"] == "SimpleVault":
                for f in c["functions"]:
                    if f["name"] == "withdraw":
                        f["modifiers"] = ["onlyOwner"]
        report = {r["contract"]: r for r in self.gen(bp)}
        self.assertTrue(any("admin-only" in s for s in report["SimpleVault"]["skipped"]))

    def test_struct_constructor_blocks_until_configured(self):
        bp = self.scan()
        for c in bp["contracts"]:
            if c["name"] == "SimpleVault":
                c["constructor"]["params"] = [{"type": "Config", "name": "cfg", "location": "memory"}]
                c["constructor"]["params"][0]["type"] = "Vault.Config"
        report = {r["contract"]: r for r in self.gen(bp, only={"SimpleVault"})}
        self.assertEqual(report["SimpleVault"]["handler"], "not generated")
        cfg = {"contracts": {"SimpleVault": {"constructor_args": ["abi.decode(hex\"\", (uint256))"]}}}
        report = {r["contract"]: r for r in self.gen(bp, config=cfg, only={"SimpleVault"})}
        self.assertEqual(report["SimpleVault"]["handler"], "written")

    def test_regeneration_is_idempotent_and_check_detects_drift(self):
        bp = self.scan()
        self.gen(bp)
        again = self.gen(bp, force=True, dry_run=True)
        self.assertFalse(injector.is_stale(again))
        (self.root / "test" / "foundryguard" / "SimpleVault" / "Handler.sol").write_text("// edited\n")
        self.assertTrue(injector.is_stale(self.gen(bp, force=True, dry_run=True)))

    def test_cli_run_and_check(self):
        args = ["--root", str(self.root), "--backend", "regex", "--no-build"]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(foundryguard.main(["check", *args]), 1)  # nothing generated yet
            self.assertEqual(foundryguard.main(["run", *args, "--report-md", str(self.tmp / "r.md"),
                                                "--sarif", str(self.tmp / "r.sarif")]), 0)
            self.assertEqual(foundryguard.main(["check", *args]), 0)
        self.assertIn("| `SimpleVault` |", (self.tmp / "r.md").read_text())
        self.assertEqual(json.loads((self.tmp / "r.sarif").read_text())["version"], "2.1.0")

    def test_init_writes_valid_config(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(foundryguard.main(["init", "--root", str(self.root)]), 0)
        self.assertIsInstance(fg_parser.load_config(self.root), dict)


class ReportingTests(unittest.TestCase):
    def test_forge_json_to_sarif(self):
        data = {"test/foundryguard/X/Invariant.t.sol:XGuardInvariantTest": {"test_results": {
            "invariant_solvency()": {"status": "Failure", "reason": "vault holds less", "counterexample": {
                "Sequence": [{"signature": "deposit(uint256,uint256,uint256)"}]}},
            "afterInvariant()": {"status": "Success"},
        }}}
        failed = reporting.failed_tests(data)
        self.assertEqual(len(failed), 1)
        self.assertIn("deposit(uint256,uint256,uint256)", failed[0][3])
        sarif = reporting.sarif_from_forge(data, Path("."))
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
        self.assertIn("1 of 2 test(s) passed", reporting.markdown_from_forge(data))


if __name__ == "__main__":
    unittest.main()
