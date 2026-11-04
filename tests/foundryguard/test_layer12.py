"""Layer 12 tests: the Web2-to-Web3 bridge validator (web_surface.py) and its place in the score."""

from __future__ import annotations

import contextlib
import io
import json
import os
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
import web_surface  # noqa: E402

BRIDGE = Path(__file__).resolve().parent / "fixtures" / "bridge"
REQUIRE_SOLC = os.environ.get("FOUNDRYGUARD_REQUIRE_SOLC") == "1"
HAVE_SOLC = REQUIRE_SOLC or bool(compiler.discover_compilers())
needs_solc = unittest.skipUnless(HAVE_SOLC, "no solc / solcjs on this machine")


def bridge_rules(findings) -> set[tuple[str, str, int]]:
    return {(f.rule, f.file, f.line) for f in findings if f.layer == web_surface.LAYER}


def run_cli(argv: list[str]) -> tuple[int, str]:
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        code = foundryguard.main(argv)
    return code, buf.getvalue()


class FixtureCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="foundryguard-l12-"))
        self.weak = self.tmp / "weak"
        self.safe = self.tmp / "safe"
        shutil.copytree(BRIDGE / "weak", self.weak)
        shutil.copytree(BRIDGE / "safe", self.safe)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


class WeakBridgeTests(FixtureCase):
    def test_every_seam_defect_is_found_at_its_line(self):
        result, _ = scoring.score_path(self.weak)
        self.assertEqual(bridge_rules(result.findings), {
            # backend: who may make the server sign or send
            ("BRIDGE-SIGNING-ORACLE", "backend/mint_api.py", 20),
            ("BRIDGE-OPEN-RELAYER", "backend/relayer.js", 13),
            ("BRIDGE-SIGNED-INPUT-UNCHECKED", "backend/claims.ts", 27),
            # backend: key handling
            ("BRIDGE-KEY-LOGGED", "backend/mint_api.py", 10),
            ("BRIDGE-KEY-FROM-REQUEST", "backend/mint_api.py", 26),
            ("BRIDGE-MNEMONIC-LITERAL", "backend/relayer.js", 5),
            ("BRIDGE-KEY-CLIENT", "web/components/MintButton.tsx", 3),
            ("BRIDGE-KEY-CLIENT", "web/components/MintButton.tsx", 7),
            ("BRIDGE-RPC-KEY", "web/components/MintButton.tsx", 4),
            ("BRIDGE-RPC-KEY", "backend/mint_api.py", 11),
            # backend: nonces, receipts, events
            ("BRIDGE-WEAK-NONCE", "backend/claims.ts", 8),
            ("BRIDGE-TX-NONCE-RACE", "backend/relayer.js", 12),
            ("BRIDGE-RECEIPT-STATUS", "backend/relayer.js", 14),
            ("BRIDGE-REORG", "backend/relayer.js", 26),
            # the pair: backend vs contract
            ("BRIDGE-TYPEHASH-DRIFT", "backend/claims.ts", 27),
            ("BRIDGE-DOMAIN-DRIFT", "backend/claims.ts", 10),
            ("BRIDGE-SIG-REPLAY", "contracts/ClaimBook.sol", 22),
            ("BRIDGE-DEADLINE-UNENFORCED", "contracts/ClaimBook.sol", 22),
            ("BRIDGE-SIG-REPLAY", "contracts/WeakDrop.sol", 14),
            ("BRIDGE-ABI-DRIFT", "backend/relayer.js", 19),
            ("BRIDGE-ABI-DRIFT", "backend/relayer.js", 23),
            # contract alone
            ("BRIDGE-SIG-NO-DOMAIN", "contracts/WeakDrop.sol", 14),
            ("BRIDGE-RAW-ECRECOVER", "contracts/WeakDrop.sol", 14),
        })

    def test_signing_sites_are_paired_with_their_verifiers(self):
        result, _ = scoring.score_path(self.weak)
        links = {(l["sign"]["file"], l["sign"]["line"]): l for l in result.bridge["links"]}
        mint = links[("backend/mint_api.py", 20)]
        self.assertEqual((mint["verify"]["contract"], mint["verify"]["function"]), ("WeakDrop", "mintWithSig"))
        self.assertEqual(mint["status"], "oracle")
        self.assertEqual(mint["sign"]["route"], "/mint-signature")
        self.assertFalse(mint["sign"]["auth"])
        claim = links[("backend/claims.ts", 27)]
        self.assertEqual((claim["verify"]["contract"], claim["verify"]["function"]), ("ClaimBook", "claim"))
        self.assertEqual(claim["status"], "replayable")
        self.assertTrue(claim["sign"]["auth"])
        self.assertIn("struct fields differ", claim["notes"])
        self.assertTrue(claim["verify"]["chain_bound"] and claim["verify"]["contract_bound"])
        self.assertFalse(claim["verify"]["replay_guard"])

    def test_bridge_findings_sink_the_score_and_reach_the_report(self):
        result, _ = scoring.score_path(self.weak)
        self.assertEqual(result.score, 1)
        self.assertTrue(all(f.points >= 0 for f in result.findings))
        out = self.tmp / "report"
        result2, page = scoring.simulate(str(self.weak), run_forge=False, out_dir=out)
        html = page.read_text(encoding="utf-8")
        self.assertIn("<h2>Bridge map</h2>", html)
        self.assertIn("WeakDrop.mintWithSig", html)
        self.assertIn("L11 web2-web3 bridge", html)
        data = json.loads((out / scoring.SCORE_JSON).read_text())
        self.assertEqual(len(data["bridge"]["links"]), 2)
        self.assertGreaterEqual(data["bridge"]["contract_calls_checked"], 2)

    def test_bridge_cli_fails_on_high(self):
        code, out = run_cli(["bridge", str(self.weak)])
        self.assertEqual(code, 1)
        self.assertIn("oracle", out)
        self.assertIn("BRIDGE-SIGNING-ORACLE", out)
        code, out = run_cli(["bridge", str(self.weak), "--json", "--fail-on", "NONE"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual({l["status"] for l in data["bridge"]["links"]}, {"oracle", "replayable"})

    def test_score_cli_prints_the_bridge_map(self):
        code, out = run_cli(["score", str(self.weak), "--out", str(self.tmp / "r")])
        self.assertEqual(code, 0)
        self.assertIn("bridge map (2 signing site(s))", out)


class SafeBridgeTests(FixtureCase):
    def test_hardened_pair_is_bound_and_clean(self):
        result, _ = scoring.score_path(self.safe)
        self.assertEqual(bridge_rules(result.findings), set())
        (link,) = result.bridge["links"]
        self.assertEqual(link["status"], "bound")
        self.assertEqual(link["verify"]["function"], "claim")
        self.assertTrue(link["verify"]["replay_guard"] and link["verify"]["deadline"])
        self.assertTrue(link["sign"]["auth"] and link["sign"]["bounded"])
        code, _ = run_cli(["bridge", str(self.safe)])
        self.assertEqual(code, 0)

    @needs_solc
    def test_fixture_contracts_compile(self):
        for root in (self.weak, self.safe):
            files = sorted(p.relative_to(root).as_posix() for p in (root / "contracts").glob("*.sol"))
            res = compiler.compile_with_solc(root, files)
            self.assertEqual(len([u for u in res.units if u.endswith(".sol")]), len(files))


def analyze(files: dict[str, str]) -> web_surface.BridgeReport:
    return web_surface.analyze(list(files.items()))


OZ_DROP = """
pragma solidity 0.8.24;
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
contract Drop is EIP712("Drop", "1"), Nonces {
    bytes32 public constant MINT_TYPEHASH = keccak256("Mint(address to,uint256 amount,uint256 nonce,uint256 deadline)");
    address public signer;
    function mint(address to, uint256 amount, uint256 deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(MINT_TYPEHASH, to, amount, _useNonce(to), deadline)));
        require(ECDSA.recover(digest, sig) == signer, "sig");
    }
}
"""

VIEM_SIGNER = """
import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
const account = privateKeyToAccount(process.env.SIGNER_KEY);
const client = createWalletClient({ account, transport: http(process.env.RPC_URL) });
export async function sign(to, amount, nonce, deadline) {
  return client.signTypedData({
    domain: { name: "Drop", version: "1", chainId: 8453 },
    types: { Mint: [
      { name: "to", type: "address" }, { name: "amount", type: "uint256" },
      { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
    ] },
    primaryType: "Mint",
    message: { to, amount, nonce, deadline },
  });
}
"""


class BridgeUnitTests(unittest.TestCase):
    def test_openzeppelin_eip712_with_nonces_is_bound(self):
        rep = analyze({"src/Drop.sol": OZ_DROP})
        (v,) = rep.verifies
        self.assertEqual((v.method, v.chain_bound, v.contract_bound, v.replay_guard, v.deadline),
                         ("eip712", True, True, True, True))
        self.assertEqual(v.typehash.name, "Mint")
        self.assertEqual((v.domain_name, v.domain_version), ("Drop", "1"))
        self.assertEqual(bridge_rules(rep.findings), set())

    def test_backend_domain_missing_verifying_contract_is_drift(self):
        rep = analyze({"src/Drop.sol": OZ_DROP, "api/sign.js": VIEM_SIGNER})
        (link,) = rep.links
        self.assertEqual(link.verify.function, "mint")
        self.assertEqual(link.status, "drift")
        titles = [f.title for f in rep.findings if f.rule == "BRIDGE-DOMAIN-DRIFT"]
        self.assertEqual(len(titles), 1)
        self.assertIn("verifyingContract", titles[0])

    def test_unlinked_server_signature_without_domain_or_nonce(self):
        src = """
from eth_account import Account
from eth_account.messages import encode_defunct
signer = Account.from_key(PRIVATE_KEY)
def voucher(user, amount):
    msg = encode_defunct(text=f"{user}:{amount}")
    return signer.sign_message(msg)
"""
        rep = analyze({"svc/voucher.py": src})
        self.assertEqual({f.rule for f in rep.findings}, {"BRIDGE-SIG-UNBOUND", "BRIDGE-SIG-NO-NONCE"})
        self.assertEqual(rep.links[0].status, "replayable")

    def test_fastapi_route_with_auth_and_bounds_is_not_an_oracle(self):
        base = """
from fastapi import APIRouter, Depends
from eth_account import Account
router = APIRouter()
signer = Account.from_key(KEY)

@router.post("/sign")
async def sign(body: MintRequest{auth}):
    if body.amount > MAX_MINT:
        raise ValueError("too much")
    digest = make_digest(body.to, body.amount, CHAIN_ID, CONTRACT_ADDRESS, body.nonce)
    return signer.sign_message(digest)
"""
        open_rep = analyze({"api/sign.py": base.replace("{auth}", "")})
        self.assertIn("BRIDGE-SIGNING-ORACLE", {f.rule for f in open_rep.findings})
        self.assertEqual(open_rep.signs[0].handler.route, "/sign")
        closed = analyze({"api/sign.py": base.replace("{auth}", ", user=Depends(get_current_user)")})
        self.assertEqual({f.rule for f in closed.findings} & {"BRIDGE-SIGNING-ORACLE", "BRIDGE-SIGNED-INPUT-UNCHECKED"},
                         set())

    def test_next_route_handler_is_detected(self):
        src = """
import { Wallet } from "ethers";
const wallet = new Wallet(process.env.SIGNER_KEY!);
export async function POST(request: Request) {
  const { to, amount } = await request.json();
  const sig = await wallet.signMessage(JSON.stringify({ to, amount }));
  return Response.json({ sig });
}
"""
        rep = analyze({"app/api/sign/route.ts": src})
        self.assertIn("BRIDGE-SIGNING-ORACLE", {f.rule for f in rep.findings})

    def test_receipt_status_checked_is_clean(self):
        src = """
import { createPublicClient, http } from "viem";
const client = createPublicClient({ transport: http(process.env.RPC_URL) });
export async function settle(hash) {
  const receipt = await client.waitForTransactionReceipt({ hash, confirmations: 3 });
  if (receipt.status !== "success") throw new Error("reverted");
  return receipt;
}
"""
        self.assertEqual(analyze({"svc/settle.js": src}).findings, [])
        unchecked = src.replace('  if (receipt.status !== "success") throw new Error("reverted");\n', "")
        self.assertEqual([f.rule for f in analyze({"svc/settle.js": unchecked}).findings], ["BRIDGE-RECEIPT-STATUS"])

    def test_packed_collision_on_two_dynamic_values(self):
        sol = """
pragma solidity 0.8.24;
contract Notes {
    address public signer;
    mapping(bytes32 => bool) public used;
    function post(string calldata a, string calldata b, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline);
        bytes32 h = keccak256(abi.encodePacked(a, b, deadline, block.chainid, address(this)));
        require(!used[h]);
        used[h] = true;
        address who = ecrecover(h, v, r, s);
        require(who != address(0) && who == signer);
    }
}
"""
        rep = analyze({"src/Notes.sol": sol})
        self.assertEqual({f.rule for f in rep.findings}, {"BRIDGE-PACKED-COLLISION"})

    def test_signature_helpers_are_followed(self):
        sol = """
pragma solidity 0.8.24;
contract Gate {
    address public signer;
    function enter(bytes32 h, uint8 v, bytes32 r, bytes32 s) external { _check(h, v, r, s); }
    function _check(bytes32 h, uint8 v, bytes32 r, bytes32 s) internal view {
        require(ecrecover(h, v, r, s) == signer);
    }
}
"""
        rep = analyze({"src/Gate.sol": sol})
        self.assertEqual([v.function for v in rep.verifies], ["enter"])
        self.assertEqual({f.rule for f in rep.findings},
                         {"BRIDGE-SIG-NO-DOMAIN", "BRIDGE-RAW-ECRECOVER", "BRIDGE-SIG-REPLAY", "BRIDGE-SIG-NO-EXPIRY"})

    def test_quiet_on_code_without_a_chain(self):
        self.assertTrue(analyze({"app.py": "from flask import Flask\napp = Flask(__name__)\n"}).empty)
        self.assertFalse(web_surface.relevant("app.py", "print('hello')"))
        self.assertTrue(web_surface.relevant("x.ts", "import { ethers } from 'ethers'"))

    def test_python_cleaner_keeps_offsets(self):
        src = 'x = "a # not a comment"  # comment\ny = """multi\nline"""\n'
        clean = web_surface.clean_python(src)
        self.assertEqual(len(clean), len(src))
        self.assertEqual(clean.count("\n"), src.count("\n"))
        self.assertNotIn("comment", clean)
        self.assertNotIn("multi", clean)
        self.assertIn("a # not", web_surface.clean_python(src, blank_strings=False))


if __name__ == "__main__":
    unittest.main()
