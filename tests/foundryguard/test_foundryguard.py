"""FoundryGuard unit tests. Run with `python3 -m unittest discover -s tests/foundryguard -v` or pytest."""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import ai_generator  # noqa: E402
import compiler  # noqa: E402
import foundryguard  # noqa: E402
import injector  # noqa: E402
import parser as fg_parser  # noqa: E402
import reporter  # noqa: E402
import reporting  # noqa: E402
from blueprints import hook_reentrancy, transient_storage  # noqa: E402

logging.disable(logging.CRITICAL)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE = FIXTURES / "project"
HOOKS_FIXTURE = FIXTURES / "hooks"
TRANSIENT_FIXTURE = FIXTURES / "transient"
LIBS_FIXTURE = FIXTURES / "libs"
AST_OUTPUT = FIXTURES / "ast" / "solc-output.json"
HOOKS_AST_OUTPUT = FIXTURES / "ast" / "hooks-solc-output.json"
TRANSIENT_AST_OUTPUT = FIXTURES / "ast" / "transient-solc-output.json"
FORGE_STDOUT = FIXTURES / "forge" / "leaky-stdout.txt"
FORGE_JSON = FIXTURES / "forge" / "leaky-results.json"
FORGE1_STDOUT = FIXTURES / "forge" / "hooks-stdout-forge1.txt"


# Tests that compile need solc or solcjs. CI sets FOUNDRYGUARD_REQUIRE_SOLC=1 so they can never be skipped there.
REQUIRE_SOLC = os.environ.get("FOUNDRYGUARD_REQUIRE_SOLC") == "1"
HAVE_SOLC = REQUIRE_SOLC or bool(compiler.discover_compilers())
needs_solc = unittest.skipUnless(HAVE_SOLC, "no solc / solcjs on this machine (set FOUNDRYGUARD_REQUIRE_SOLC=1 to fail instead)")
REQUIRE_LIBS = os.environ.get("FOUNDRYGUARD_REQUIRE_LIBS") == "1"
HAVE_LIBS = REQUIRE_LIBS or (HAVE_SOLC and (LIBS_FIXTURE / "node_modules" / "solady").is_dir()
                             and (LIBS_FIXTURE / "node_modules" / "@openzeppelin" / "contracts").is_dir())
needs_libs = unittest.skipUnless(HAVE_LIBS, "run `npm install` in tests/foundryguard/fixtures/libs first")


def contracts(blueprint: dict) -> dict[str, dict]:
    return {c["name"]: c for c in blueprint["contracts"] if not c["external"]}


def without_ozvault(root: Path) -> Path:
    """The committed AST fixture has no OpenZeppelin sources, so OZVault is compiled only in the forge CI job."""
    (root / "src" / "OZVault.sol").unlink(missing_ok=True)
    return root


class ProjectCase(unittest.TestCase):
    fixture = FIXTURE
    ast_fixture = AST_OUTPUT

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="foundryguard-"))
        self.root = self.tmp / "project"
        shutil.copytree(self.fixture, self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, config: dict | None = None) -> dict:
        """Blueprint from the committed solc AST of the fixture (no compiler needed)."""
        return fg_parser.build_blueprint(self.root, [], config=config, ast_path=str(self.ast_fixture))

    def compile(self, root: Path | None = None, paths: list[str] | None = None, **kw) -> dict:
        """Blueprint from a fresh compile of the fixture."""
        return fg_parser.build_blueprint(root or self.root, paths or [], **kw)

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

    def test_public_getters_and_state_var_details(self):
        cs = contracts(self.scan())
        stakedOf = next(v for v in cs["RewardStaking"]["state_vars"] if v["name"] == "stakedOf")
        self.assertEqual(stakedOf["visibility"], "public")
        self.assertEqual(stakedOf["getter"]["signature"], "stakedOf(address)")
        self.assertEqual(stakedOf["getter"]["returns"], ["uint256"])
        self.assertTrue(stakedOf["type_id"].startswith("t_mapping$_t_address_$_t_uint256"))

    def test_exact_signatures_selectors_and_types(self):
        cs = contracts(self.scan())
        fns = {f["signature"]: f for f in cs["SimpleVault"]["functions"]}
        self.assertEqual(fns["deposit(uint256)"]["selector"], "b6b55f25")
        self.assertEqual(fns["withdraw(uint256)"]["selector"], "2e1a7d4d")
        self.assertEqual(fns["deposit(uint256)"]["params"][0]["type_id"], "t_uint256")
        self.assertEqual(fns["deposit(uint256)"]["mutability"], "nonpayable")
        ctor = cs["SimpleVault"]["constructor"]["params"][0]
        self.assertEqual(ctor["type"], "IERC20")
        self.assertTrue(ctor["type_id"].startswith("t_contract$_IERC20_$"))
        sv = cs["SimpleVault"]
        self.assertEqual((sv["fqn"], sv["origin"], sv["linearized_bases"]),
                         ("src/SimpleVault.sol:SimpleVault", "project", ["src/SimpleVault.sol:SimpleVault"]))
        bp = self.scan()
        self.assertEqual((bp["schema"], bp["backend"]), (fg_parser.SCHEMA, "ast"))

    def test_prebuilt_ast_missing(self):
        with self.assertRaises(compiler.SolidityError):
            fg_parser.build_blueprint(self.root, [], ast_path=str(self.root / "nowhere"))
        with self.assertRaises(compiler.SolidityError):
            fg_parser.build_blueprint(self.root, [], build_dir="nowhere", run_build=False)

    def _broken_ast(self, mutate) -> Path:
        data = json.loads(self.ast_fixture.read_text())
        mutate(data)
        path = self.tmp / "broken-ast.json"
        path.write_text(json.dumps(data))
        return path

    @staticmethod
    def _contract_node(data: dict, unit: str, name: str) -> dict:
        return next(n for n in data["sources"][unit]["ast"]["nodes"]
                    if n.get("nodeType") == "ContractDefinition" and n["name"] == name)

    def test_validation_flags_malformed_nodes(self):
        def drop_mutability(data):
            fn = next(n for n in self._contract_node(data, "src/SimpleVault.sol", "SimpleVault")["nodes"]
                      if n.get("nodeType") == "FunctionDefinition" and n["name"] == "deposit")
            del fn["stateMutability"]

        with self.assertRaises(fg_parser.ASTValidationError) as ctx:
            fg_parser.build_blueprint(self.root, [], ast_path=str(self._broken_ast(drop_mutability)))
        self.assertIn("FunctionDefinition without stateMutability", str(ctx.exception))
        self.assertIn("SimpleVault", ctx.exception.diagnostics[0].message)

        def untyped(data):
            fn = next(n for n in self._contract_node(data, "src/SimpleVault.sol", "SimpleVault")["nodes"]
                      if n.get("nodeType") == "FunctionDefinition" and n["name"] == "deposit")
            fn["parameters"]["parameters"][0]["typeDescriptions"] = {}

        with self.assertRaises(fg_parser.ASTValidationError) as ctx:
            fg_parser.build_blueprint(self.root, [], ast_path=str(self._broken_ast(untyped)))
        self.assertIn("without type analysis", str(ctx.exception))

        def bad_src(data):
            self._contract_node(data, "src/Token.sol", "Token")["src"] = "garbage"

        with self.assertRaises(fg_parser.ASTValidationError) as ctx:
            fg_parser.build_blueprint(self.root, [], ast_path=str(self._broken_ast(bad_src)))
        self.assertIn("bad src 'garbage'", str(ctx.exception))

        def dangling_base(data):
            self._contract_node(data, "src/Token.sol", "Token")["linearizedBaseContracts"].append(999999)

        with self.assertRaises(fg_parser.ASTValidationError) as ctx:
            fg_parser.build_blueprint(self.root, [], ast_path=str(self._broken_ast(dangling_base)))
        self.assertIn("999999", str(ctx.exception))

    def test_legacy_ast_rejected(self):
        legacy = self.tmp / "legacy.json"
        legacy.write_text(json.dumps({"sources": {"src/A.sol": {"ast": {"name": "SourceUnit", "children": []}}}}))
        with self.assertRaises(compiler.SolidityError) as ctx:
            fg_parser.build_blueprint(self.root, [], ast_path=str(legacy))
        self.assertIn("legacy solc AST", str(ctx.exception))

    def test_regex_backend_removed(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            foundryguard.main(["scan", "--root", str(self.root), "--backend", "regex"])
        self.assertIn("removed", str(ctx.exception.code))

    def test_pragma_ranges(self):
        sat = compiler.satisfies
        self.assertTrue(sat("0.8.24", "^0.8.20"))
        self.assertFalse(sat("0.9.0", "^0.8.20"))
        self.assertTrue(sat("0.8.24", ">=0.8.0 <0.9.0"))
        self.assertFalse(sat("0.8.24", ">=0.8.25"))
        self.assertTrue(sat("0.8.24", "0.8.24"))
        self.assertTrue(sat("0.7.6", "^0.6.0 || ^0.7.0"))
        self.assertTrue(sat("0.8.9", "~0.8.1"))
        self.assertTrue(sat("0.8.10", "0.8.4 - 0.8.12"))
        self.assertEqual(compiler.parse_version("0.8.24+commit.e11b9ed9"), (0, 8, 24))

    def test_remappings_keep_context_and_infer_libs(self):
        (self.root / "remappings.txt").write_text("ctx:@x/=lib/x/\n")
        (self.root / "lib" / "solady" / "src").mkdir(parents=True)
        (self.root / "lib" / "openzeppelin-contracts" / "contracts").mkdir(parents=True)
        remaps = compiler.load_remappings(self.root)
        self.assertIn("ctx:@x/=lib/x/", remaps)
        self.assertIn("solady/=lib/solady/src/", remaps)
        # foundry.toml's explicit entry wins over the inferred one for the same prefix.
        self.assertEqual([r for r in remaps if r.startswith("@openzeppelin/contracts/=")],
                         ["@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"])

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

    def test_v1_blueprint_still_generates_the_same_suites(self):
        bp = self.scan()
        v2 = self.gen(bp, force=True, dry_run=True)
        self.gen(bp)
        v1 = json.loads(json.dumps(bp))
        v1["schema"] = "foundryguard.blueprint/v1"
        for c in v1["contracts"]:
            for key in ("fqn", "linearized_bases", "bases", "interfaces", "origin"):
                c.pop(key, None)
            for v in c["state_vars"]:
                v.pop("getter", None)
        again = self.gen(v1, force=True, dry_run=True)
        self.assertFalse(injector.is_stale(again))
        self.assertEqual([r["contract"] for r in v2], [r["contract"] for r in again])

    def test_cli_run_and_check(self):
        args = ["--root", str(self.root), "--ast", str(self.ast_fixture)]
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


@needs_solc
class CompilerTests(ProjectCase):
    """Live compiles with the local solc / solcjs (always run in CI)."""

    def test_live_compile_matches_committed_ast(self):
        for fixture, ast in ((FIXTURE, AST_OUTPUT), (HOOKS_FIXTURE, HOOKS_AST_OUTPUT)):
            root = self.tmp / f"live-{fixture.name}"
            shutil.copytree(fixture, root)
            live = self.compile(without_ozvault(root))
            committed = fg_parser.build_blueprint(root, [], ast_path=str(ast))
            self.assertEqual(live["compiler"]["driver"] in ("solc", "solcjs"), True)
            self.assertEqual(live["contracts"], committed["contracts"],
                             f"{ast.name} is stale: regenerate it with `foundryguard scan --save-ast`")

    def test_syntax_error_stops_in_the_parse_pass(self):
        without_ozvault(self.root)
        (self.root / "src" / "Broken.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract Broken {\n    function deposit(uint256 amount) external {\n"
            "        uint256 x = amount\n    }\n}\n")
        (self.root / "src" / "Typo.sol").write_text(
            "pragma solidity ^0.8.20;\ncontract Typo { function f() external { undefinedThing(); } }\n")
        with self.assertRaises(compiler.SolidityError) as ctx:
            self.compile()
        err = ctx.exception
        self.assertIn("syntax error", err.headline)
        self.assertEqual([(d.type, d.file, d.line) for d in err.diagnostics], [("ParserError", "src/Broken.sol", 5)])
        # Once the syntax is fixed, the full analysis reports the type-level error with its position.
        (self.root / "src" / "Broken.sol").unlink()
        with self.assertRaises(compiler.SolidityError) as ctx:
            self.compile()
        self.assertEqual([(d.type, d.file, d.line) for d in ctx.exception.diagnostics],
                         [("DeclarationError", "src/Typo.sol", 2)])

    def test_missing_dependency_is_an_error_with_a_hint(self):
        with self.assertRaises(compiler.SolidityError) as ctx:
            self.compile()
        err = ctx.exception
        self.assertTrue(err.diagnostics and all(d.file == "src/OZVault.sol" for d in err.diagnostics))
        self.assertIn("not found", err.diagnostics[0].message)
        self.assertIn("forge install", err.hint)

    def test_save_ast_round_trip(self):
        without_ozvault(self.root)
        saved = self.tmp / "saved.json"
        live = self.compile(save_ast=str(saved))
        again = fg_parser.build_blueprint(self.root, [], ast_path=str(saved))
        self.assertEqual(live["contracts"], again["contracts"])
        self.assertEqual(again["compiler"]["driver"], "prebuilt")

    def test_explicit_compiler_must_exist(self):
        with self.assertRaises(SystemExit):
            self.compile(solc=str(self.tmp / "no-such-solc"))


@needs_libs
class LibraryLineageTests(ProjectCase):
    """OpenZeppelin (node_modules) and Solady (remapped) parents resolved from the AST."""

    fixture = LIBS_FIXTURE

    def setUp(self) -> None:
        super().setUp()
        self.bp = self.compile()
        self.cs = contracts(self.bp)

    def test_solady_vault_lineage_and_inherited_flows(self):
        v = self.cs["SoladyVault"]
        self.assertEqual(v["linearized_bases"], [
            "src/SoladyVault.sol:SoladyVault", "node_modules/solady/src/auth/Ownable.sol:Ownable",
            "node_modules/solady/src/tokens/ERC4626.sol:ERC4626", "node_modules/solady/src/tokens/ERC20.sol:ERC20"])
        by_fqn = {c["fqn"]: c for c in self.bp["contracts"]}
        self.assertEqual({by_fqn[f]["origin"] for f in v["linearized_bases"][1:]}, {"solady"})
        self.assertEqual(v["categories"], {})  # every flow is inherited
        report = {r["contract"]: r for r in self.gen(self.bp)}["SoladyVault"]
        self.assertEqual(sorted(report["flows"]), ["deposit:deposit(uint256,address)", "deposit:mint(uint256,address)",
                                                   "withdraw:redeem(uint256,address,address)",
                                                   "withdraw:withdraw(uint256,address,address)"])
        self.assertIn("invariant_erc4626_previewsHonoured", report["invariants"])

    def test_openzeppelin_staking_modifiers_mutability_and_getters(self):
        s = self.cs["OZStaking"]
        self.assertEqual([f.split(":")[1] for f in s["linearized_bases"]], ["OZStaking", "ReentrancyGuard", "Ownable", "Context"])
        self.assertTrue(s["linearized_bases"][1].startswith("@openzeppelin/contracts/"))
        fns = {f["name"]: f for f in s["functions"]}
        self.assertEqual(fns["stake"]["modifiers"], ["nonReentrant"])
        self.assertEqual((fns["sweep"]["mutability"], fns["sweep"]["modifiers"]), ("payable", ["onlyOwner"]))
        getters = {v["name"]: v.get("getter") for v in s["state_vars"]}
        self.assertEqual(getters["lockedUntil"]["signature"], "lockedUntil(address,uint256)")
        self.assertEqual(getters["lockedUntil"]["returns"], ["uint64"])
        self.assertIsNone(getters["MAX_LOCK"])
        consts = {v["name"]: v["mutability"] for v in s["state_vars"]}
        self.assertEqual((consts["MAX_LOCK"], consts["stakingToken"]), ("constant", "immutable"))
        report = {r["contract"]: r for r in self.gen(self.bp)}["OZStaking"]
        self.assertIn("invariant_actorBalancesBoundedByTotal", report["invariants"])

    def test_same_named_parents_are_told_apart(self):
        solady, oz = self.cs["SoladyShare"], self.cs["OZShare"]
        self.assertEqual(solady["inherits"], ["ERC20"])
        self.assertEqual(oz["inherits"], ["ERC20"])
        self.assertEqual(solady["bases"][0]["fqn"], "node_modules/solady/src/tokens/ERC20.sol:ERC20")
        self.assertEqual(oz["bases"][0]["fqn"], "@openzeppelin/contracts/token/ERC20/ERC20.sol:ERC20")
        self.assertEqual(oz["interfaces"], ["IERC20Errors", "IERC20Metadata", "IERC20"])
        self.assertEqual(solady["interfaces"], [])
        # Both are plain mint-only tokens, recognised through the lineage, so neither is fuzzed.
        targets = {r["contract"] for r in self.gen(self.bp)}
        self.assertEqual(targets, {"SoladyVault", "OZStaking"})


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
    ast_fixture = HOOKS_AST_OUTPUT

    def test_detects_hook_callbacks(self):
        cs = contracts(self.scan())
        self.assertEqual(cs["HookedVault"]["hooks"]["callbacks"], ["afterWithdraw", "beforeDeposit"])
        self.assertEqual(cs["UnlockPool"]["hooks"]["callbacks"], ["unlockCallback"])
        self.assertFalse(cs["IVaultHooks"]["hooks"])
        # Callback entry points are not value flows.
        self.assertEqual(cs["IUnlockCallback"]["categories"], {})

    @needs_solc
    def test_callback_detection_patterns(self):
        (self.root / "src" / "Caller.sol").write_text("""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;
            interface IHooks { function beforeSwap(address, uint256) external; }
            interface IUnlockCallback { function unlockCallback(bytes calldata) external returns (bytes memory); }
            interface IVaultHooksLike { function afterDeposit(address, uint256) external; }
            interface IOracle { function beforeUpdate() external; }
            interface ICallee { function uniswapV3SwapCallback(int256, int256, bytes calldata) external; }
            interface IToken { function transferFrom(address, address, uint256) external returns (bool); }
            contract Caller {
                struct PoolKey { IHooks hooks; }
                IToken token;
                IOracle oracle;
                address hookAddr;
                function run(PoolKey calldata key, uint256 amount, bytes calldata data) external {
                    key.hooks.beforeSwap(msg.sender, amount);
                    bytes memory r = IUnlockCallback(msg.sender).unlockCallback(data);
                    IVaultHooksLike(hookAddr).afterDeposit{gas: 50000}(msg.sender, amount);
                    token.transferFrom(msg.sender, address(this), amount);
                    oracle.beforeUpdate();
                    ICallee(msg.sender).uniswapV3SwapCallback(0, 0, data);
                    r;
                }
            }
        """)
        caller = contracts(self.compile(paths=["src/Caller.sol"]))["Caller"]
        run = next(f for f in caller["functions"] if f["name"] == "run")
        found = {(c["name"], c["receiver"]) for c in run["callbacks"]}
        self.assertEqual(found, {("beforeSwap", "key.hooks"), ("unlockCallback", "msg.sender"),
                                 ("afterDeposit", "hookAddr"), ("uniswapV3SwapCallback", "msg.sender")})

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
        bp = fg_parser.build_blueprint(root, [], ast_path=str(AST_OUTPUT))
        injector.inject(bp, root, root / "test" / "foundryguard", None, 4, "1e24", False, False, None)
        self.assertNotIn("HookProbe", (root / "test" / "foundryguard" / "SimpleVault" / "Handler.sol").read_text())


LOCK_SLOT = "0xb5b3158153d0aaada99ce72b624e94e7a176c6db390b7f301526554778835892"
ENTRY_SLOT = "0x42921539d5967844d1f3f10ed40f47d09e34318dd2aa14b0efc78898cdbcf2ba"


class TransientPresetTests(ProjectCase):
    fixture = TRANSIENT_FIXTURE
    ast_fixture = TRANSIENT_AST_OUTPUT

    def test_detects_tstore_and_tload_in_functions_and_modifiers(self):
        bp = self.scan()
        cs = contracts(bp)
        tr = cs["TransientStaking"]["transient"]
        self.assertEqual(tr["tstore_slots"], sorted([LOCK_SLOT, ENTRY_SLOT]))
        self.assertEqual(tr["tload_slots"], sorted([LOCK_SLOT, ENTRY_SLOT]))
        self.assertEqual(tr["sites"], ["function _accrue", "function _endEntry", "function stake", "modifier nonReentrant"])
        self.assertEqual(tr["dynamic"], [])
        lock = [o for o in tr["ops"] if o["site"] == "modifier nonReentrant"]
        self.assertEqual([(o["op"], o["slot"], o["expr"]) for o in lock],
                         [("tload", LOCK_SLOT, "LOCK_SLOT"), ("tstore", LOCK_SLOT, "LOCK_SLOT"), ("tstore", LOCK_SLOT, "LOCK_SLOT")])
        self.assertTrue(all(o["line"] > 0 for o in tr["ops"]))
        # The leaky child writes nothing itself; its parent's slots reach it through the lineage.
        self.assertEqual(cs["LeakyTransientStaking"]["transient"], {})
        self.assertEqual(bp["summary"]["transient_contracts"], 1)

    def test_fixed_and_leaky_get_the_between_calls_check(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        for name in ("TransientStaking", "LeakyTransientStaking"):
            r = report[name]
            self.assertIn("invariant_transient_slotsClearedBetweenCalls", r["invariants"])
            self.assertEqual(r["transient"]["slots"], sorted([LOCK_SLOT, ENTRY_SLOT]))
            self.assertEqual(r["setup_notes"], [])
        handler = self.read("LeakyTransientStaking", "Handler.sol")
        self.assertIn("contract LeakyTransientStakingTransientHarness is LeakyTransientStaking {", handler)
        self.assertIn("constructor(IERC20Minimal token0) LeakyTransientStaking(token0) { }", handler)
        self.assertIn('import { LeakyTransientStaking, IERC20Minimal } from "../../../src/TransientStaking.sol";', handler)
        self.assertIn(f"transientSlots.push({LOCK_SLOT});", handler)
        self.assertIn("function transientSequence(uint256 seed) external {", handler)
        self.assertIn("try this.stake(_seed(s, 0), _seed(s, 1)) { } catch { }", handler)
        self.assertIn("try this.claimPoints(_seed(s, 0)) { } catch { }", handler)
        # The check runs after every successful flow, inside the same transaction.
        self.assertEqual(handler.count("_transientCheck();"), 3)
        inv = self.read("LeakyTransientStaking", "Invariant.t.sol")
        self.assertIn("type(LeakyTransientStakingTransientHarness).creationCode", inv)
        self.assertIn("LeakyTransientStakingGuardHandler.transientSequence.selector", inv)
        self.assertIn("LeakyTransientStakingTransientHarness } from \"./Handler.sol\";", inv)
        self.assertIn("assertEq(handler.ghost_transientLeaks(), 0,", inv)

    def test_config_ignores_extends_or_disables_slots(self):
        cfg = {"contracts": {"TransientStaking": {"transient_ignore": [ENTRY_SLOT], "transient_slots": ["0x01"]},
                             "LeakyTransientStaking": {"transient": False}}}
        report = {r["contract"]: r for r in self.gen(self.scan(), config=cfg)}
        self.assertEqual(report["TransientStaking"]["transient"]["slots"], ["0x" + "0" * 63 + "1", LOCK_SLOT])
        self.assertEqual(report["TransientStaking"]["transient"]["ignored"], [ENTRY_SLOT])
        self.assertIsNone(report["LeakyTransientStaking"]["transient"])
        self.assertNotIn("invariant_transient_slotsClearedBetweenCalls", report["LeakyTransientStaking"]["invariants"])
        self.assertNotIn("TransientHarness", self.read("LeakyTransientStaking", "Handler.sol"))

    def test_slot_folding_and_parsing(self):
        self.assertEqual(transient_storage.parse_number("0x1_0"), 16)
        self.assertEqual(transient_storage.parse_number("1e18"), 10 ** 18)
        self.assertEqual(transient_storage.parse_number("2.5e1"), 25)
        self.assertIsNone(transient_storage.parse_number("\"abc\""))
        lit = lambda v: {"nodeType": "YulLiteral", "kind": "number", "value": v}
        call = lambda f, *a: {"nodeType": "YulFunctionCall", "functionName": {"name": f}, "arguments": list(a)}
        scope = transient_storage._Scope({}, lambda _id: None)
        self.assertEqual(transient_storage._eval(call("add", lit("0x10"), lit("1")), scope), 17)
        self.assertEqual(transient_storage._eval(call("sub", lit("0"), lit("1")), scope), (1 << 256) - 1)
        self.assertIsNone(transient_storage._eval(call("add", lit("1"), call("caller")), scope))
        self.assertEqual(transient_storage.yul_text(call("add", lit("1"), call("caller"))), "add(1, caller())")

    @needs_solc
    def test_slot_resolution_patterns(self):
        (self.root / "src" / "Slots.sol").write_text("""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.24;
            uint256 constant FILE_SLOT = 0xaa;
            contract Base {
                uint256 internal constant BASE = 0x100;
                uint256 internal constant DERIVED = BASE;
                uint256 internal constant ONE_ETHER = 1 ether;
            }
            contract Slots is Base {
                function run(uint256 a, bool flag) external {
                    assembly {
                        tstore(FILE_SLOT, a)
                        let s := 0x99
                        tstore(s, a)
                        tstore(add(BASE, 1), a)
                        tstore(DERIVED, a)
                        tstore(ONE_ETHER, a)
                        tstore(add(BASE, caller()), a)
                        let t := 0x77
                        if flag { t := a }
                        tstore(t, 1)
                        function clear(slot) { tstore(slot, 0) }
                        clear(0x55)
                    }
                }
            }
            contract ReadOnly {
                function peek() external view returns (uint256 v) {
                    assembly { v := tload(0x1) }
                }
            }
        """)
        cs = contracts(self.compile(paths=["src/Slots.sol"]))
        tr = cs["Slots"]["transient"]
        hexes = lambda *vals: sorted(transient_storage.slot_hex(v) for v in vals)
        self.assertEqual(tr["tstore_slots"], hexes(0xaa, 0x99, 0x101, 0x100, 10 ** 18))
        self.assertEqual(tr["dynamic"], ["tstore(add(BASE, caller())) in function run", "tstore(slot) in function run",
                                         "tstore(t) in function run"])
        self.assertEqual(cs["ReadOnly"]["transient"]["tload_slots"], hexes(1))
        self.assertIsNone(transient_storage.analyze("ReadOnly", [cs["ReadOnly"]]))
        plan = transient_storage.analyze("Slots", [cs["Slots"], cs["Base"]])
        self.assertEqual(len(plan.slots), 5)
        self.assertIn("transient_slots", plan.notes[0])

    def test_projects_without_transient_storage_are_unchanged(self):
        root = self.tmp / "plain"
        shutil.copytree(FIXTURE, root)
        bp = fg_parser.build_blueprint(root, [], ast_path=str(AST_OUTPUT))
        report = injector.inject(bp, root, root / "test" / "foundryguard", None, 4, "1e24", False, False, None)
        self.assertTrue(all(r["transient"] is None for r in report))
        handler = (root / "test" / "foundryguard" / "SimpleVault" / "Handler.sol").read_text()
        self.assertNotIn("transient", handler.lower())


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

    def test_metrics_count_each_campaign_once(self):
        m = reporter.metrics(reporter.parse_text(FORGE_STDOUT.read_text(), "forge.log"))
        # afterInvariant is a hook, not a property; three separate pre-1.x campaigns; one fuzz test with 3 runs
        self.assertEqual((m.invariants, m.invariants_broken, m.campaigns), (3, 1, 3))
        self.assertEqual((m.invariant_calls, m.fuzz_runs, m.fuzz_inputs), (2050, 3, 2053))
        self.assertAlmostEqual(m.wall_time, 0.43)
        self.assertAlmostEqual(m.suite_time, 0.4221)
        # forge 1.x prints one shared campaign's stats on every invariant of the contract
        m1 = reporter.metrics(reporter.parse_text(FORGE1_STDOUT.read_text(), "forge.log"))
        self.assertEqual((m1.campaigns, m1.invariant_runs, m1.invariant_calls), (2, 64, 2048))
        self.assertAlmostEqual(m1.time, 1.23)
        mj = reporter.metrics(reporter.parse_text(FORGE_JSON.read_text(), "results.json"))
        self.assertEqual((mj.wall_time, round(mj.suite_time, 3), mj.invariant_calls), (None, 0.412, 2050))

    def test_attributed_campaign_counted_once(self):
        target = "test/X.t.sol:XTest"
        text = json.dumps({target: {"test_results": {
            "invariant_a()": {"status": "Failure", "kind": {"Invariant": {"runs": 8, "calls": 400, "reverts": 0}},
                              "counterexample": {"Sequence": [{"signature": "deposit(uint256)", "args": "1"}]}},
            "invariant_b()": {"status": "Success"}}}}) + "\n" + json.dumps(
            {"event": "failure", "invariant": "invariant_b", "target": target, "reason": "b"}) + "\n"
        m = reporter.metrics(reporter.parse_text(text))
        self.assertEqual((m.invariants, m.campaigns, m.invariant_calls), (2, 1, 400))

    def test_parse_duration(self):
        self.assertAlmostEqual(reporter.parse_duration("412.10ms"), 0.4121)
        self.assertAlmostEqual(reporter.parse_duration("1m 2s"), 62.0)
        self.assertAlmostEqual(reporter.parse_duration("12µs"), 12e-6)
        self.assertAlmostEqual(reporter.parse_duration({"secs": 1, "nanos": 500000000}), 1.5)
        self.assertIsNone(reporter.parse_duration("soon"))

    def test_trace_frames_storage_changes(self):
        frames = reporter.trace_frames([
            "  [52000] H::deposit(3, 10)", "    ├─  storage changes:", "    │   @ 2: 0 → 10",
            "    ├─ [500] Token::transfer(1) ", "    └─ ← [Stop]", "  [3000] T::invariant_x()"])
        self.assertEqual([(f.contract, f.func) for f in frames], [("H", "deposit"), ("T", "invariant_x")])
        self.assertEqual(frames[0].storage, [("2", "0", "10")])

    def test_report_html(self):
        root = Path(tempfile.mkdtemp(prefix="foundryguard-report-"))
        self.addCleanup(shutil.rmtree, root, True)
        run = reporter.parse_text(FORGE_STDOUT.read_text(), "forge.log")
        run.failures[0].traces[:0] = ["  [1] LeakyVaultGuardHandler::withdraw(3, 1000)", "    │   @ 2: 1000 → 990"]
        page = reporter.render_html(run, root, generated="now")
        self.assertTrue(page.startswith("<!doctype html>"))
        for banned in ("<script", "gradient", "animation", "transition", "http://", "https://"):
            self.assertNotIn(banned, page)
        self.assertIn("#2e7d32", page)
        self.assertIn("#c62828", page)
        self.assertIn('<span class="badge FAILED">FAILED</span>', page)
        self.assertIn('<details class="failure" open>', page)
        self.assertIn('<span class="fn">withdraw</span>(3, 1000)', page)
        self.assertIn('<td class="n"><span class="down">-10</span></td>', page)  # storage drift on slot 2
        self.assertIn("drift (left - right)</th><td>-10</td>", page)
        self.assertIn("<td>Invariants checked</td><td class=\"n\">3</td>", page)
        self.assertIn("<td>Fuzz inputs</td><td class=\"n\">2,053</td>", page)
        self.assertIn("<td>Execution time</td><td class=\"n\">430.00 ms</td>", page)
        empty = reporter.render_html(reporter.Run(source="<x>", fmt="forge JSON"), root)
        self.assertIn("No test results were found", empty)
        self.assertIn("&lt;x&gt;", empty)

    def test_write_report_writes_html_beside_markdown(self):
        root = Path(tempfile.mkdtemp(prefix="foundryguard-report-"))
        self.addCleanup(shutil.rmtree, root, True)
        run = reporter.parse_text(FORGE_JSON.read_text(), "results.json")
        reporter.write_report(run, root)
        self.assertIn("invariant_tokenSolvency()", (root / reporter.HTML_FILE).read_text())
        self.assertIn("| Invariants checked | Fuzz inputs | Execution time |", (root / reporter.REPORT_FILE).read_text())
        (root / reporter.HTML_FILE).unlink()
        reporter.write_report(run, root, html=False)
        self.assertFalse((root / reporter.HTML_FILE).exists())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            foundryguard.main(["report", str(FORGE_JSON), "--root", str(root), "--html", str(root / "out" / "r.html")])
        self.assertTrue((root / "out" / "r.html").is_file())


AI_HANDLER = """```solidity
// File: Handler.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {Ledger} from "../../../src/Token.sol";
contract LedgerAIHandler is Test {
    Ledger internal ledger;
    uint256 public ghostMinted;
    constructor(Ledger l) { ledger = l; }
    function mint(uint256 seed, uint256 amount) external {
        amount = bound(amount, 0, 1e24);
        ledger.mint(address(uint160(bound(seed, 1, 4))), amount);
        ghostMinted += amount;
    }
}
```"""
AI_TEST = """```solidity
// File: Invariant.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {Ledger} from "../../../src/Token.sol";
import {LedgerAIHandler} from "./Handler.sol";
contract LedgerAIInvariantTest is Test {
    Ledger internal ledger;
    LedgerAIHandler internal handler;
    function setUp() public {
        ledger = new Ledger();
        handler = new LedgerAIHandler(ledger);
        targetContract(address(handler));
    }
    // catches supply drifting from what was minted
    function invariant_supplyMatchesMinted() public view {
        assertEq(ledger.totalSupply(), handler.ghostMinted());
    }
}
```"""


class AIGeneratorTests(ProjectCase):
    """Layer 06: no network here, every call goes through a fake transport."""

    def blueprint(self) -> dict:
        bp = self.scan()
        token = next(c for c in bp["contracts"] if c["name"] == "Token")
        custom = json.loads(json.dumps(token))
        custom["name"], custom["fqn"] = "Ledger", "src/Token.sol:Ledger"
        custom["linearized_bases"] = ["src/Token.sol:Ledger"]
        custom["categories"] = {}
        for f in custom["functions"]:
            f["category"] = None
        bp["contracts"].append(custom)
        return bp

    def settings(self, provider="anthropic"):
        key = "ANTHROPIC_API_KEY" if provider == "anthropic" else "OPENAI_API_KEY"
        return ai_generator.settings_from({}, {key: "test-key"})

    def fake(self, answer: str, provider="anthropic"):
        calls = []

        def send(url, headers, body, timeout):
            calls.append((url, headers, body))
            if provider == "anthropic":
                return {"content": [{"type": "text", "text": answer}]}
            return {"choices": [{"message": {"content": answer}}]}
        return send, calls

    def run_ai(self, answer: str, provider="anthropic", **kw):
        send, calls = self.fake(answer, provider)
        out = self.root / "test" / "foundryguard"
        report = injector.inject(self.blueprint(), self.root, out, kw.get("only"), 4, "1e24", kw.get("force", False),
                                 kw.get("dry_run", False), {}, self.settings(provider), send)
        return {r["contract"]: r for r in report}, calls

    def test_settings_need_a_key(self):
        self.assertIsNone(ai_generator.settings_from({}, {}))
        s = ai_generator.settings_from({}, {"ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "o"})
        self.assertEqual((s.provider, s.model), ("anthropic", ai_generator.DEFAULT_MODELS["anthropic"]))
        s = ai_generator.settings_from({"ai": {"provider": "openai", "model": "m"}},
                                       {"OPENAI_API_KEY": "o", "OPENAI_BASE_URL": "http://localhost:8000/v1/"})
        self.assertEqual((s.provider, s.model, s.base_url), ("openai", "m", "http://localhost:8000/v1"))
        self.assertNotIn("api_key", repr(s))
        with self.assertRaises(ai_generator.AIError):
            ai_generator.settings_from({}, {"FOUNDRYGUARD_AI_PROVIDER": "x", "OPENAI_API_KEY": "o"})

    def test_without_ai_custom_contracts_are_skipped(self):
        report = self.gen(self.blueprint())
        self.assertNotIn("Ledger", {r["contract"] for r in report})

    def test_custom_contract_gets_ai_suite(self):
        report, calls = self.run_ai(AI_HANDLER + "\n" + AI_TEST)
        self.assertEqual(len(calls), 1)  # only Ledger: preset targets never reach the model
        url, headers, body = calls[0]
        self.assertTrue(url.endswith("/v1/messages"))
        self.assertEqual(headers["x-api-key"], "test-key")
        prompt = body["messages"][0]["content"]
        self.assertIn("function mint(address to, uint256 amount) external", prompt)
        self.assertIn("LedgerAIHandler", prompt)
        self.assertNotIn("@notice", prompt)  # comments are stripped from the source
        r = report["Ledger"]
        self.assertEqual((r["handler"], r["invariant"]), ("written", "written"))
        self.assertEqual(r["invariants"], ["invariant_supplyMatchesMinted"])
        self.assertIn("SimpleVault", report)  # the preset suites are still generated
        self.assertTrue(self.read("Ledger", "Handler.sol").startswith(ai_generator.GENERATED_MARKER))
        self.assertNotIn("// File:", self.read("Ledger", "Invariant.t.sol"))
        # existing files are kept and the model is not asked again; dry runs never call it
        again, calls = self.run_ai(AI_HANDLER + AI_TEST)
        self.assertEqual(calls, [])
        self.assertTrue(again["Ledger"]["handler"].startswith("kept"))
        dry, calls = self.run_ai(AI_HANDLER + AI_TEST, force=True, dry_run=True)
        self.assertEqual(calls, [])
        self.assertFalse(injector.is_stale([dry["Ledger"]]))

    def test_openai_compatible_endpoint(self):
        report, calls = self.run_ai(AI_HANDLER + AI_TEST, provider="openai", only={"Ledger"})
        url, headers, body = calls[0]
        self.assertEqual(url, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(headers["authorization"], "Bearer test-key")
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertEqual(report["Ledger"]["handler"], "written")

    def test_dangerous_or_incomplete_answers_are_refused(self):
        ffi = AI_TEST.replace("targetContract(address(handler));",
                              "targetContract(address(handler)); vm.ffi(new string[](0));")
        report, _ = self.run_ai(AI_HANDLER + ffi, only={"Ledger"})
        self.assertEqual(report["Ledger"]["handler"], "not generated")
        self.assertIn("vm.ffi", report["Ledger"]["blocked"][0])
        self.assertFalse((self.root / "test" / "foundryguard" / "Ledger").exists())
        report, _ = self.run_ai(AI_HANDLER, only={"Ledger"})
        self.assertIn("did not contain", report["Ledger"]["blocked"][0])
        renamed = AI_HANDLER.replace("contract LedgerAIHandler", "contract Other")
        report, _ = self.run_ai(renamed + AI_TEST, only={"Ledger"})
        self.assertIn("does not define contract LedgerAIHandler", report["Ledger"]["blocked"][0])

    def test_strip_comments_keeps_strings(self):
        src = 'string s = "a // b"; // gone\n/* gone\n too */ uint x;\n\n'
        self.assertEqual(ai_generator.strip_comments(src), 'string s = "a // b";\nuint x;')

    def test_cli_ai_flag_without_key_warns(self):
        args = ["--root", str(self.root), "--ast", str(self.ast_fixture), "--ai"]
        env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                                                                  "FOUNDRYGUARD_AI_PROVIDER")}
        err = io.StringIO()
        with unittest.mock.patch.dict(os.environ, env, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(foundryguard.main(["run", *args]), 0)
        self.assertIn("neither ANTHROPIC_API_KEY nor OPENAI_API_KEY", err.getvalue())


if __name__ == "__main__":
    unittest.main()


ECOSYSTEM_FIXTURE = FIXTURES / "ecosystem"
ECOSYSTEM_AST_OUTPUT = FIXTURES / "ast" / "ecosystem-solc-output.json"
FORGE_STD_STUB = FIXTURES / "forge-std-stub"


class EcosystemTests(ProjectCase):
    fixture = ECOSYSTEM_FIXTURE
    ast_fixture = ECOSYSTEM_AST_OUTPUT

    def test_links_from_declared_types_and_address_casts(self):
        cs = contracts(self.scan())
        links = {l["var"]: l for l in cs["OracleVault"]["links"]}
        oracle = links["oracle"]
        self.assertEqual((oracle["type"], oracle["how"], oracle["role"], oracle["type_kind"]),
                         ("IPriceOracle", "declared", "oracle", "interface"))
        self.assertEqual(oracle["type_fqn"], "src/IPriceOracle.sol:IPriceOracle")
        self.assertEqual([(s["kind"], s["param"], s["index"]) for s in oracle["set_in"]], [("constructor", "oracle_", 1)])
        self.assertEqual(oracle["calls"], ["price"])
        self.assertEqual(oracle["used_in"], ["deposit(uint256)", "valueOf(address)"])
        self.assertEqual(links["token"]["role"], "token")
        self.assertEqual(links["token"]["calls"], ["transfer", "transferFrom"])
        # `address public oracle` only becomes a link because the code casts it to IPriceOracle.
        leaky = {l["var"]: l for l in cs["LeakyOracleVault"]["links"]}["oracle"]
        self.assertEqual((leaky["type"], leaky["how"], leaky["declared_as"]), ("IPriceOracle", "cast", "address"))
        self.assertEqual(leaky["used_in"], ["balanceOf(address)", "deposit(uint256)", "totalAssets()", "withdraw(uint256)"])
        self.assertEqual(cs["PriceFeed"]["links"], [])

    def test_dependency_matrix_and_deploy_order(self):
        bp = self.scan()
        eco = bp["ecosystem"]
        self.assertEqual(bp["summary"]["ecosystems"], 1)
        self.assertEqual(bp["summary"]["linked_contracts"], 2)
        status = {(e["from"], e["var"]): (e["status"], e["to"], e["via"]) for e in eco["edges"]}
        self.assertEqual(status[("OracleVault", "oracle")], ("member", "PriceFeed", "constructor"))
        self.assertEqual(status[("LeakyOracleVault", "oracle")], ("member", "PriceFeed", "constructor"))
        self.assertEqual(status[("OracleVault", "token")], ("mock", None, "constructor"))
        (cl,) = eco["clusters"]
        self.assertEqual(cl["name"], "PriceFeed")
        self.assertEqual(cl["members"], ["PriceFeed", "LeakyOracleVault", "OracleVault"])
        self.assertEqual(cl["roots"], ["LeakyOracleVault", "OracleVault"])
        self.assertEqual(cl["matrix"]["rows"], [[0, 0, 0], [1, 0, 0], [1, 0, 0]])
        self.assertEqual(cl["cycles"], [])

    def test_master_handler_deploys_and_wires_every_member(self):
        report = {r["contract"]: r for r in self.gen(self.scan())}
        # The vaults need PriceFeed to work, so they only get the ecosystem suite.
        self.assertEqual(sorted(report), ["PriceFeedEcosystem"])
        r = report["PriceFeedEcosystem"]
        self.assertEqual(r["ecosystem"]["deploy_order"], ["PriceFeed", "LeakyOracleVault", "OracleVault"])
        self.assertEqual(r["ecosystem"]["replaces"], ["LeakyOracleVault", "OracleVault"])
        self.assertEqual(r["actions"], ["PriceFeed.keeper:setPrice(uint256)"])
        self.assertEqual(len(r["flows"]), 4)
        self.assertIn("invariant_ecosystem_wiringIntact", r["invariants"])
        self.assertIn("invariant_ecosystem_LeakyOracleVault_tokenSolvency", r["invariants"])
        self.assertIn("invariant_ecosystem_OracleVault_tokenSolvency", r["invariants"])
        self.assertIn("invariant_ecosystem_tokenConservation_token", r["invariants"])
        handler = self.read("PriceFeedEcosystem", "Handler.sol")
        self.assertIn("contract PriceFeedEcosystemHandler is CommonBase, StdUtils {", handler)
        self.assertIn("constructor(PriceFeed _priceFeed, LeakyOracleVault _leakyOracleVault, OracleVault _oracleVault, "
                      "address[] memory _tokens, address _admin) {", handler)
        self.assertIn("function priceFeed_setPrice(uint256 newPriceSeed) external {", handler)
        self.assertIn("vm.prank(admin);\n        try priceFeed.setPrice(newPrice_) {", handler)
        self.assertIn("uint256 amount_max = leakyOracleVault.balanceOf(actor);", handler)
        self.assertIn('ghost_in["OracleVault:assets"] += amount_;', handler)
        self.assertIn("try this.priceFeed_setPrice(_seed(s, 0)) { } catch { }", handler)
        inv = self.read("PriceFeedEcosystem", "Invariant.t.sol")
        self.assertLess(inv.index("priceFeed = PriceFeed("), inv.index("leakyOracleVault = LeakyOracleVault("))
        self.assertIn("address(priceFeed) /* address oracle_: PriceFeed */", inv)
        self.assertIn("address(priceFeed) /* IPriceOracle oracle_: PriceFeed */", inv)
        self.assertEqual(inv.count("address(token) /* IERC20 token_ */"), 2)  # one mock shared by both vaults
        self.assertIn('assertEq(address(oracleVault.oracle()), address(priceFeed), "OracleVault.oracle no longer points at PriceFeed");', inv)
        self.assertIn("leakyOracleVault.totalAssets(),", inv)
        self.assertIn("PriceFeedEcosystemHandler.ecosystemSequence.selector", inv)
        md = reporting.markdown_report(list(report.values()), self.scan())
        self.assertIn("(ecosystem: PriceFeed, LeakyOracleVault, OracleVault)", md)
        self.assertIn("LeakyOracleVault  x . .", md)

    def test_regeneration_is_idempotent(self):
        bp = self.scan()
        self.gen(bp)
        again = self.gen(bp)
        self.assertFalse(injector.is_stale(again))

    def test_config_disables_excludes_and_binds(self):
        bp = self.scan()
        off = {r["contract"]: r for r in self.gen(bp, config={"ecosystem": {"enabled": False}})}
        self.assertEqual(sorted(off), ["LeakyOracleVault", "OracleVault"])  # back to standalone suites
        self.assertTrue(any("placeholder address(this)" in n for n in off["OracleVault"]["setup_notes"]))
        shutil.rmtree(self.root / "test")
        r = self.gen(bp, config={"targets": {"exclude": ["LeakyOracleVault"]}})[0]
        self.assertEqual(r["ecosystem"]["members"], ["PriceFeed", "OracleVault"])
        self.assertEqual(r["ecosystem"]["matrix"]["rows"], [[0, 0], [1, 0]])
        self.assertNotIn("leakyOracleVault", self.read("PriceFeedEcosystem", "Handler.sol"))
        bound = fg_parser.build_blueprint(self.root, [], config={"ecosystem": {"bind": {"OracleVault.oracle": "mock"}}},
                                          ast_path=str(self.ast_fixture))
        status = {(e["from"], e["var"]): e["status"] for e in bound["ecosystem"]["edges"]}
        self.assertEqual(status[("OracleVault", "oracle")], "mock")
        self.assertEqual(bound["ecosystem"]["clusters"][0]["members"], ["PriceFeed", "LeakyOracleVault"])

    def test_projects_without_links_are_unchanged(self):
        root = self.tmp / "plain"
        shutil.copytree(FIXTURE, root)
        bp = fg_parser.build_blueprint(root, [], ast_path=str(AST_OUTPUT))
        self.assertEqual(bp["ecosystem"]["clusters"], [])
        self.assertTrue(all(e["status"] == "mock" for e in bp["ecosystem"]["edges"]))
        report = injector.inject(bp, root, root / "test" / "foundryguard", None, 4, "1e24", False, False, None)
        self.assertFalse(any(r.get("ecosystem") for r in report))

    @needs_solc
    def test_generated_ecosystem_compiles(self):
        self.gen(self.scan())
        shutil.copytree(FORGE_STD_STUB / "src", self.root / "lib" / "forge-std" / "src")
        files = sorted(p.relative_to(self.root).as_posix() for p in (self.root / "test").rglob("*.sol"))
        result = compiler.compile_with_solc(self.root, files, "auto")
        self.assertIn("test/foundryguard/PriceFeedEcosystem/Invariant.t.sol", result.units)
        self.assertEqual([d.as_dict() for d in result.diagnostics if d.severity == "error"], [])

    @needs_solc
    def test_setter_created_inferred_and_cycle_links(self):
        (self.root / "src" / "Patterns.sol").write_text("""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.24;
            interface IStrategy { function invest(uint256 amount) external; }
            interface IRateModel { function rate() external view returns (uint256); }
            contract Strategy is IStrategy {
                function invest(uint256) external { }
            }
            contract Escrow { uint256 public held; }
            contract RateA is IRateModel { function rate() external pure returns (uint256) { return 1; } }
            contract RateB is IRateModel { function rate() external pure returns (uint256) { return 2; } }
            contract Hub {
                address public owner = msg.sender;
                IStrategy public strategy;
                Escrow public escrow;
                IRateModel internal model;
                modifier onlyOwner() { require(msg.sender == owner); _; }
                constructor(IRateModel model_) {
                    escrow = new Escrow();
                    _setModel(model_);
                }
                function _setModel(IRateModel m) internal { model = m; }
                function setStrategy(address s) external onlyOwner { strategy = IStrategy(s); }
                function deposit(uint256 amount) external { strategy.invest(amount * model.rate()); }
            }
            contract Left { Right public right; constructor(Right r) { right = r; } }
            contract Right { Left public left; constructor(Left l) { left = l; } }
        """)
        bp = self.compile(paths=["src/Patterns.sol"], config={"ecosystem": {"bind": {"IRateModel": "RateB"}}})
        hub = {l["var"]: l for l in contracts(bp)["Hub"]["links"]}
        self.assertEqual(hub["strategy"]["set_in"][0]["kind"], "setter")
        self.assertEqual(hub["strategy"]["set_in"][0]["function"], "setStrategy(address)")
        self.assertEqual(hub["escrow"]["created"], "Escrow")
        self.assertTrue(hub["model"]["set_in"][0].get("inferred"))  # set through an internal helper
        self.assertEqual(hub["strategy"]["calls"], ["invest"])
        edges = {(e["from"], e["var"]): e for e in bp["ecosystem"]["edges"]}
        self.assertEqual((edges[("Hub", "strategy")]["to"], edges[("Hub", "strategy")]["via"]), ("Strategy", "setter"))
        self.assertEqual((edges[("Hub", "escrow")]["status"], edges[("Hub", "escrow")]["via"]), ("created", "created"))
        self.assertEqual(edges[("Hub", "model")]["to"], "RateB")
        clusters = {cl["name"]: cl for cl in bp["ecosystem"]["clusters"]}
        self.assertEqual(clusters["Hub"]["members"], ["Escrow", "RateB", "Strategy", "Hub"])
        cycle = next(cl for cl in clusters.values() if "Left" in cl["members"])
        self.assertEqual(cycle["cycles"], [["Left", "Right"]])

        report = {r["contract"]: r for r in self.gen(bp, only={"Hub", "Left"})}
        self.assertIn("cycle", report["LeftEcosystem"]["blocked"][0])
        inv = self.read("HubEcosystem", "Invariant.t.sol")
        self.assertIn("escrow = Escrow(payable(address(hub.escrow())));", inv)
        self.assertIn('abi.encodeWithSignature("setStrategy(address)", address(strategy))', inv)
        self.assertIn("address(rateB) /* IRateModel model_: RateB */", inv)
        self.assertLess(inv.index("strategy = Strategy("), inv.index("hub = Hub("))
        shutil.copytree(FORGE_STD_STUB / "src", self.root / "lib" / "forge-std" / "src")
        result = compiler.compile_with_solc(self.root, ["test/foundryguard/HubEcosystem/Invariant.t.sol"], "auto")
        self.assertIn("test/foundryguard/HubEcosystem/Handler.sol", result.units)


import healer  # noqa: E402

PRAGMA_MISMATCH = ("Source file requires different compiler version (current compiler is 0.8.19+commit.7dd6d404.Linux.g++) "
                   "- note that nightly builds are considered to be strictly less than the released version")


class HealerTests(ProjectCase):
    """Layer 08: Generate -> Compile -> Heal -> Re-compile."""

    def out(self) -> Path:
        return self.root / "test" / "foundryguard"

    def handler(self) -> Path:
        return self.out() / "SimpleVault" / "Handler.sol"

    def problem(self, needle: bytes, message: str, severity: str = "error", type_: str = "TypeError",
                code: str = "", span: bool = False) -> healer.Problem:
        data = self.handler().read_bytes()
        start = data.index(needle)
        return healer.Problem(severity, type_, code, message, "test/foundryguard/SimpleVault/Handler.sol", start,
                              start + len(needle) if span else None)

    def fake_compiler(self, *rounds: list):
        """Each call returns the next list of problems (as a thunk, so offsets match the file at that point)."""
        calls = list(rounds)

        def run():
            problems = calls.pop(0)() if calls else []
            return healer.Build("fake", "0.8.19", problems)
        return run

    def test_rules_rewrite_the_reported_lines(self):
        self.gen(self.scan(), only={"SimpleVault"})
        h = self.handler()
        src = h.read_text()
        src = src.replace("address[] memory _tokens", "address[] _tokens")
        src = src.replace("function actorCount() external view", "function actorCount() view")
        src = src.replace("function warp(uint256 dtSeed) external {", "function warp(uint256 dtSeed) external override {")
        h.write_text(src)
        compile_fn = self.fake_compiler(lambda: [
            self.problem(b"pragma solidity", PRAGMA_MISMATCH, type_="ParserError", code="5333"),
            self.problem(b"address[] _tokens", 'Data location must be "memory" or "calldata" for parameter in function, '
                                               'but none was given.', type_="TypeError", code="6651", span=True),
            self.problem(b"function actorCount", 'No visibility specified. Did you intend to add "external"?',
                         type_="SyntaxError", code="4937"),
            self.problem(b"function warp", "Function has override specified but does not override anything.",
                         code="7792"),
        ], lambda: [])
        result = healer.heal(self.root, self.out(), compile_fn=compile_fn)
        self.assertEqual(result.status, "healed")
        self.assertEqual(sorted(f["rule"] for f in result.fixes), ["data-location", "override", "pragma", "visibility"])
        healed = h.read_text()
        self.assertIn("pragma solidity ^0.8.19;", healed)
        self.assertIn("address[] memory _tokens", healed)
        self.assertIn("function actorCount() external view returns (uint256) {", healed)
        self.assertIn("function warp(uint256 dtSeed) external {", healed)
        log = json.loads((self.out() / healer.HEAL_FILE).read_text())
        self.assertEqual(log["schema"], healer.HEAL_SCHEMA)
        self.assertEqual(len(log["files"]["SimpleVault/Handler.sol"]), 4)

    def test_heal_log_is_replayed_on_regenerate(self):
        bp = self.scan()
        self.gen(bp, only={"SimpleVault"})
        compile_fn = self.fake_compiler(
            lambda: [self.problem(b"pragma solidity", PRAGMA_MISMATCH, type_="ParserError", code="5333")], lambda: [])
        self.assertEqual(healer.heal(self.root, self.out(), compile_fn=compile_fn).status, "healed")
        # A forced regenerate renders the template again and keeps the fix; check does not call it stale.
        self.gen(bp, only={"SimpleVault"}, force=True)
        self.assertIn("pragma solidity ^0.8.19;", self.handler().read_text())
        self.assertFalse(injector.is_stale(self.gen(bp, only={"SimpleVault"}, dry_run=True)))

    def test_warning_rules_and_opt_out(self):
        self.gen(self.scan(), only={"SimpleVault"})
        h = self.handler()
        h.write_text(h.read_text().replace("function unitCount() external view", "function unitCount() external"))
        warn = lambda: [self.problem(b"function unitCount", "Function state mutability can be restricted to view",  # noqa: E731
                                     severity="warning", type_="Warning", code="2018")]
        off = healer.heal(self.root, self.out(), warnings=False, compile_fn=self.fake_compiler(warn))
        self.assertEqual((off.status, off.fixes, off.warnings), ("passed", [], 1))
        on = healer.heal(self.root, self.out(), compile_fn=self.fake_compiler(warn, lambda: []))
        self.assertEqual(on.status, "healed")
        self.assertIn("function unitCount() external view returns (uint256) {", h.read_text())

    def test_errors_outside_generated_files_are_not_touched(self):
        self.gen(self.scan(), only={"SimpleVault"})
        before = (self.root / "src" / "SimpleVault.sol").read_bytes()
        bad = lambda: [healer.Problem("error", "TypeError", "6651", 'Data location must be "memory" or "calldata" '  # noqa: E731
                                      "for parameter in function, but none was given.", "src/SimpleVault.sol", 10, 20)]
        result = healer.heal(self.root, self.out(), compile_fn=self.fake_compiler(bad, bad))
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.fixes, [])
        self.assertIn("src/SimpleVault.sol", result.remaining[0])
        self.assertEqual((self.root / "src" / "SimpleVault.sol").read_bytes(), before)

    def test_unresolved_imports_skip_instead_of_fail(self):
        self.gen(self.scan(), only={"SimpleVault"})
        missing = lambda: [healer.Problem("error", "ParserError", "6275", 'Source "forge-std/Test.sol" not found: '  # noqa: E731
                                          "File not found.", "test/foundryguard/SimpleVault/Invariant.t.sol", 0, 10)]
        result = healer.heal(self.root, self.out(), compile_fn=self.fake_compiler(missing))
        self.assertEqual(result.status, "skipped")
        self.assertIn("imports did not resolve", result.note)

    def test_forge_text_diagnostics_fallback(self):
        self.gen(self.scan(), only={"SimpleVault"})
        text = ("Compiler run failed:\n\x1b[31mError (6651)\x1b[0m: Data location must be \"memory\" or \"calldata\" for "
                "parameter in function, but none was given.\n  --> test/foundryguard/SimpleVault/Handler.sol:41:31:\n")
        (p,) = healer.problems_from_text(text, self.root)
        self.assertEqual((p.severity, p.code, p.file), ("error", "6651", "test/foundryguard/SimpleVault/Handler.sol"))
        self.assertEqual(self.handler().read_bytes()[:p.start].count(b"\n") + 1, 41)
        doc = healer._json_document('Compiling 3 files\n{"errors": [{"severity": "warning", "type": "Warning", '
                                    '"message": "x", "sourceLocation": {"file": "a.sol", "start": 1, "end": 2}}]}')
        self.assertEqual(healer.problems_from_json(doc)[0].file, "a.sol")

    def test_gen_heals_only_when_asked_or_forge_present(self):
        bp_path = self.tmp / "bp.json"
        bp_path.write_text(json.dumps(self.scan()))
        with unittest.mock.patch.object(injector.shutil, "which", return_value=None), \
                unittest.mock.patch.object(healer, "heal") as heal, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(foundryguard.main(["gen", str(bp_path), "--root", str(self.root)]), 0)
            heal.assert_not_called()
            heal.return_value = healer.HealResult("failed", "fake", 2, remaining=["x.sol: TypeError: nope"])
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(foundryguard.main(["gen", str(bp_path), "--root", str(self.root), "--heal"]), 1)
            self.assertIn("still do not compile", err.getvalue())
            heal.reset_mock()
            foundryguard.main(["check", "--root", str(self.root), "--ast", str(self.ast_fixture), "--heal"])
            heal.assert_not_called()  # check never writes, so it never heals

    @needs_solc
    def test_live_heal_with_solc(self):
        self.gen(self.scan(), only={"SimpleVault"})
        shutil.copytree(FORGE_STD_STUB / "src", self.root / "lib" / "forge-std" / "src")
        h = self.handler()
        clean = h.read_text()
        broken = (clean.replace("address[] memory _tokens", "address[] _tokens")
                  .replace("function actorCount() external view", "function actorCount() view")
                  .replace("function warp(uint256 dtSeed) external {", "function warp(uint256 dtSeed) external view override {")
                  .replace("function unitCount() external view returns", "function unitCount() external pure returns"))
        h.write_text(broken)
        result = healer.heal(self.root, self.out(), "auto")
        self.assertEqual(result.status, "healed", result.remaining)
        rules = {f["rule"] for f in result.fixes}
        self.assertTrue({"data-location", "visibility", "override", "mutability"} <= rules, rules)
        healed = h.read_text()
        self.assertIn("address[] memory _tokens", healed)
        self.assertIn("function warp(uint256 dtSeed) external {", healed)
        self.assertIn("function unitCount() external view returns", healed)
        files = healer.generated_files(self.root, self.out())
        self.assertEqual(healer.compile_solc(self.root, files).errors, [])
