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
import reporter  # noqa: E402
import reporting  # noqa: E402
from blueprints import hook_reentrancy  # noqa: E402

logging.disable(logging.CRITICAL)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE = FIXTURES / "project"
HOOKS_FIXTURE = FIXTURES / "hooks"
AST_OUTPUT = FIXTURES / "ast" / "solc-output.json"
HOOKS_AST_OUTPUT = FIXTURES / "ast" / "hooks-solc-output.json"
FORGE_STDOUT = FIXTURES / "forge" / "leaky-stdout.txt"
FORGE_JSON = FIXTURES / "forge" / "leaky-results.json"
FORGE1_STDOUT = FIXTURES / "forge" / "hooks-stdout-forge1.txt"


def contracts(blueprint: dict) -> dict[str, dict]:
    return {c["name"]: c for c in blueprint["contracts"] if not c["external"]}


class ProjectCase(unittest.TestCase):
    fixture = FIXTURE

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="foundryguard-"))
        self.root = self.tmp / "project"
        shutil.copytree(self.fixture, self.root)

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

    def test_token_detected_even_without_parent_source(self):
        bp = self.scan()
        for c in bp["contracts"]:
            if c["name"] == "Token":
                c["inherits"] = ["ERC20"]
                c["functions"] = [f for f in c["functions"] if f["name"] == "mint"]
        self.assertNotIn("Token", {r["contract"] for r in self.gen(bp)})

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
        self.assertIn("1 of 2 result(s) passed", reporting.markdown_from_forge(data))

    def test_shared_campaign_failure_event_names_real_invariant(self):
        target = "test/foundryguard/L/Invariant.t.sol:LGuardInvariantTest"
        text = json.dumps({target: {"test_results": {"invariant_a()": {"status": "Failure", "reason": None}}}}) + "\n" + \
            json.dumps({"event": "failure", "invariant": "invariant_tokenSolvency", "target": target,
                        "reason": "token balance below totalDeposits"}) + "\n"
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "r.json"
            path.write_text(text)
            data = reporting.load_forge_json(path)
        failed = reporting.failed_tests(data)
        self.assertEqual([(f[2], f[3]) for f in failed], [("invariant_tokenSolvency()", "token balance below totalDeposits")])
        self.assertEqual(reporting.test_count(data), 1)
        self.assertEqual(reporting.test_count({}), 0)


class HookPresetTests(ProjectCase):
    fixture = HOOKS_FIXTURE

    def test_detects_hook_callbacks(self):
        cs = contracts(self.scan())
        self.assertEqual(cs["HookedVault"]["hooks"]["callbacks"], ["afterWithdraw", "beforeDeposit"])
        self.assertEqual(cs["UnlockPool"]["hooks"]["callbacks"], ["unlockCallback"])
        self.assertFalse(cs["IVaultHooks"]["hooks"])
        # Callback entry points are not value flows.
        self.assertEqual(cs["IUnlockCallback"]["categories"], {})

    def test_callback_detection_patterns(self):
        body = """
            key.hooks.beforeSwap(msg.sender, key, params, hookData);
            bytes memory r = IUnlockCallback(msg.sender).unlockCallback(data);
            IVaultHooks(hookAddr).afterDeposit{gas: 50000}(msg.sender, amount);
            token.transferFrom(msg.sender, address(this), amount);
            oracle.beforeUpdate();
            ICallee(msg.sender).uniswapV3SwapCallback(a0, a1, data);
        """
        found = {(c["name"], c["receiver"]) for c in hook_reentrancy.detect_callbacks(body)}
        self.assertEqual(found, {("beforeSwap", "key.hooks"), ("unlockCallback", "msg.sender"),
                                 ("afterDeposit", "hookAddr"), ("uniswapV3SwapCallback", "msg.sender")})

    def test_ast_backend_detects_the_same_hooks(self):
        shutil.copy(HOOKS_AST_OUTPUT, self.root / "ast.json")
        ast = contracts(fg_parser.build_blueprint(self.root, [], backend="ast", build_dir="ast.json", run_build=False))
        rgx = contracts(self.scan())
        self.assertEqual({k: v["hooks"] for k, v in ast.items()}, {k: v["hooks"] for k, v in rgx.items()})

    def test_buggy_vault_gets_read_consistency_check(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        r = report["HookedVault"]
        self.assertIn("invariant_hook_readConsistency", r["invariants"])
        self.assertNotIn("invariant_hook_lockEngagedDuringCallback", r["invariants"])  # no lock getter
        self.assertEqual(r["hooks"]["views"], ["pricePerShare", "totalAssets", "totalSupply"])
        inv = self.read("HookedVault", "Invariant.t.sol")
        self.assertIn("hookProbes[0] /* IVaultHooks hooks_: Preset 04 hook probe */", inv)
        self.assertIn("new HookedVaultGuardHandler(target, tokens, rewardTokens, hookProbes)", inv)
        handler = self.read("HookedVault", "Handler.sol")
        self.assertIn("contract HookedVaultHookProbe {", handler)
        self.assertIn('_hookBegin("");', handler)
        self.assertIn("_hookEnd(false);", handler)

    def test_guarded_vault_gets_lock_and_reentry_checks(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        r = report["GuardedHookVault"]
        self.assertEqual(r["hooks"]["lock_getter"], "locked")
        self.assertEqual(r["hooks"]["nonreentrant_flows"], ["deposit(uint256)", "withdraw(uint256)"])
        self.assertIn("invariant_hook_lockEngagedDuringCallback", r["invariants"])
        self.assertIn("invariant_hook_guardedFlowsNotReentered", r["invariants"])
        inv = self.read("GuardedHookVault", "Invariant.t.sol")
        self.assertIn('abi.encodeWithSignature("setHooks(address)", hookProbes[0])', inv)
        handler = self.read("GuardedHookVault", "Handler.sol")
        self.assertIn('_hookBegin(abi.encodeWithSignature("withdraw(uint256)", shares_));', handler)

    def test_msg_sender_callback_with_bytes_return(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        self.assertEqual(report["UnlockPool"]["hooks"]["receivers"], ["msg.sender"])
        self.assertEqual(report["UnlockPool"]["setup_notes"], [])
        handler = self.read("UnlockPool", "Handler.sol")
        self.assertIn('import { IUnlockCallback } from "../../../src/UnlockPool.sol";', handler)
        self.assertIn('if (msg.sig == IUnlockCallback.unlockCallback.selector) return abi.encode(bytes(""));', handler)

    def test_projects_without_hooks_are_unchanged(self):
        root = self.tmp / "plain"
        shutil.copytree(FIXTURE, root)
        bp = fg_parser.build_blueprint(root, [], backend="regex", run_build=False)
        injector.inject(bp, root, root / "test" / "foundryguard", None, 4, "1e24", False, False, None)
        self.assertNotIn("HookProbe", (root / "test" / "foundryguard" / "SimpleVault" / "Handler.sol").read_text())


class ReporterTests(unittest.TestCase):
    def test_parses_forge_stdout(self):
        run = reporter.parse_text(FORGE_STDOUT.read_text(), "forge.log")
        self.assertEqual(run.fmt, "forge stdout")
        self.assertEqual((run.count(reporter.PASSED), run.count(reporter.FAILED)), (4, 2))  # recap not double-counted
        inv = next(t for t in run.failures if t.name == "invariant_tokenSolvency()")
        self.assertEqual(inv.kind, "invariant")
        self.assertEqual(inv.shrunk_from, 7)
        self.assertEqual([c.signature for c in inv.sequence], ["deposit(uint256,uint256)", "withdraw(uint256,uint256)"])
        self.assertEqual(inv.sequence[0].args, ["3", "1000000000000000000000"])  # [1e21] annotation dropped
        self.assertEqual(inv.sequence[0].target, "LeakyVaultGuardHandler")
        self.assertTrue(inv.traces)
        fuzz = next(t for t in run.failures if t.name == "testFuzz_roundTrip(uint256)")
        self.assertEqual((fuzz.kind, fuzz.reason, fuzz.sequence[0].args), ("fuzz", "assertion failed: 1 != 2", ["42"]))
        self.assertEqual(fuzz.logs, ["amount 42"])

    def test_parses_forge_1x_invariant_blocks(self):
        run = reporter.parse_text(FORGE1_STDOUT.read_text(), "forge.log")
        self.assertEqual(run.fmt, "forge stdout")
        self.assertEqual([t.name for t in run.failures], ["invariant_hook_readConsistency()"])
        self.assertEqual((run.count(reporter.PASSED), run.count(reporter.FAILED)), (7, 1))
        broken = run.failures[0]
        self.assertEqual((broken.kind, broken.runs, broken.calls), ("invariant", 32, 1024))
        self.assertTrue(broken.traces)

    def test_persisted_failure_supplies_counterexample(self):
        root = Path(tempfile.mkdtemp(prefix="foundryguard-report-"))
        self.addCleanup(shutil.rmtree, root, True)
        failures = root / "cache" / "invariant" / "failures" / "HookedVaultGuardInvariantTest" / "invariants"
        failures.mkdir(parents=True)
        (failures / "invariant_hook_readConsistency").write_text(json.dumps({"call_sequence": [
            {"sender": "0x0000000000000000000000000000000000000001", "addr": "0x00000000000000000000000000000000000000aa",
             "calldata": "0x", "contract_name": "test/foundryguard/HookedVault/Handler.sol:HookedVaultGuardHandler",
             "signature": "deposit(uint256,uint256)", "args": "0, 5"},
            {"sender": "0x0000000000000000000000000000000000000002", "addr": "0x00000000000000000000000000000000000000aa",
             "calldata": "0x", "contract_name": "test/foundryguard/HookedVault/Handler.sol:HookedVaultGuardHandler",
             "signature": "withdraw(uint256,uint256)", "args": "0, 1"}], "driver_bytecode": "0x"}))
        run = reporter.parse_text(FORGE1_STDOUT.read_text())
        path = reporter.write_report(run, root)
        md = path.read_text()
        self.assertEqual(path, root / reporter.REPORT_FILE)
        self.assertIn("#### Counter-example call trace", md)
        self.assertIn("handler.withdraw(0, 1);\n    invariant_hook_readConsistency();", md)

    def test_campaign_attributed_by_assertion_message(self):
        root = Path(tempfile.mkdtemp(prefix="foundryguard-report-"))
        self.addCleanup(shutil.rmtree, root, True)
        test_file = root / "test" / "X.t.sol"
        test_file.parent.mkdir(parents=True)
        test_file.write_text('function invariant_a() public view { assertLe(a, b, "a too big"); }\n'
                             'function invariant_b() public view { assertEq(c, 0, "c moved"); }\n')
        data = {"test/X.t.sol:XTest": {"test_results": {"invariant_a()": {"status": "Failure", "reason": "c moved: 1 != 0"}}}}
        run = reporter.parse_json(data)
        reporter.resolve_from_source(run, root)
        self.assertEqual([t.name for t in run.failures], ["invariant_b()"])

    def test_parses_forge_json(self):
        run = reporter.parse_text(FORGE_JSON.read_text(), "results.json")
        self.assertEqual(run.fmt, "forge JSON")
        inv = run.failures[0]
        self.assertEqual((inv.name, inv.calls, len(inv.sequence)), ("invariant_tokenSolvency()", 2, 2))
        self.assertEqual(inv.sequence[1].args, ["3", "1000"])

    def test_shared_campaign_event_names_real_invariant(self):
        target = "test/foundryguard/L/Invariant.t.sol:LGuardInvariantTest"
        text = json.dumps({target: {"test_results": {
            "invariant_a()": {"status": "Failure", "counterexample": {"Sequence": [{"signature": "deposit(uint256)"}]}},
            "invariant_tokenSolvency()": {"status": "Success"}}}}) + "\n" + json.dumps(
            {"event": "failure", "invariant": "invariant_tokenSolvency", "target": target, "reason": "below"}) + "\n"
        run = reporter.parse_text(text)
        broken = next(t for t in run.tests if t.name == "invariant_tokenSolvency()")
        self.assertEqual((broken.status, broken.reason, len(broken.sequence)), (reporter.FAILED, "below", 1))
        self.assertIn("invariant_tokenSolvency", next(t for t in run.tests if t.name == "invariant_a()").note)

    def test_report_markdown(self):
        root = Path(tempfile.mkdtemp(prefix="foundryguard-report-"))
        self.addCleanup(shutil.rmtree, root, True)
        handler = root / "test" / "foundryguard" / "LeakyVault" / "Handler.sol"
        handler.parent.mkdir(parents=True)
        handler.write_text("function deposit(uint256 actorSeed, uint256 amountSeed) external {}\n"
                           "function withdraw(uint256 actorSeed, uint256 amountSeed) external {}\n")
        md = reporter.render(reporter.parse_text(FORGE_STDOUT.read_text(), "forge.log"), root, generated="now")
        self.assertIn("https://img.shields.io/badge/FoundryGuard-FAILED-red", md)
        self.assertIn("https://img.shields.io/badge/PASSED-brightgreen", md)
        self.assertIn("#### Counter-example call trace", md)
        self.assertIn("`deposit(actorSeed: 3, amountSeed: 1000000000000000000000)`", md)
        self.assertIn("    handler.withdraw(3, 1000);\n    invariant_tokenSolvency();", md)
        self.assertIn("--match-test 'invariant_tokenSolvency' -vvvv", md)
        clean = reporter.render(reporter.Run(source="x", fmt="forge JSON"), root)
        self.assertIn("No test results were found", clean)

    def test_cli_report_writes_root_report_from_stdout(self):
        root = Path(tempfile.mkdtemp(prefix="foundryguard-report-"))
        self.addCleanup(shutil.rmtree, root, True)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = foundryguard.main(["report", str(FORGE_STDOUT), "--root", str(root), "--fail-on-failure",
                                    "--sarif", str(root / "r.sarif")])
        self.assertEqual(rc, 1)
        self.assertIn("invariant_tokenSolvency", (root / reporter.REPORT_FILE).read_text())
        results = json.loads((root / "r.sarif").read_text())["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(reporter.main([str(FORGE_JSON), "--root", str(root), "-o", str(root / "j.md")]), 0)
        self.assertIn("forge JSON", (root / "j.md").read_text())


if __name__ == "__main__":
    unittest.main()
