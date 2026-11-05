"""0.18: cryptography signatures FG-151..FG-170 and the scan-engine speedups.

The per-signature samples (fixtures/ultrapack/{weak,safe}/fg151..fg170) are picked up by test_layer15. This
module covers the detectors' edge cases (the shapes that must not match), and checks that the faster engine
gives the same findings as the straightforward one: per-line hint candidates, lazy file-level patterns, the
literal prefilters and the scan-scoped strip/parse memo.
"""

from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "cli"))

import scoring  # noqa: E402
import signatures  # noqa: E402
import web_surface  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
WEB_EXT = {".py": "py", ".js": "js", ".html": "html", ".php": "php"}


def _sol_rules(src: str) -> set[str]:
    found, _ = scoring.check_solidity("S.sol", src, scoring.ALL_PRESETS)
    return {f.rule for f in found}


def _web_rules(src: str, lang: str) -> set[str]:
    return {f.rule for f in scoring.check_text("a." + lang, src, lang)}


def _web_fixtures():
    for p in sorted(FIXTURES.rglob("*")):
        if p.is_file() and p.suffix in WEB_EXT and "node_modules" not in p.parts:
            yield p, WEB_EXT[p.suffix]


class CatalogTests(unittest.TestCase):
    def test_new_ids(self):
        self.assertEqual(signatures.BY_ID["FG-151"].rule, "SOL-EIP712-CACHED-DOMAIN")
        self.assertEqual(signatures.BY_ID["FG-157"].rule, "SOL-MERKLE-LEAF-64")
        self.assertEqual(signatures.BY_ID["FG-158"].rule, "WEB-CIPHER-ECB")
        self.assertEqual(signatures.BY_ID["FG-170"].rule, "WEB-LEGACY-TLS")
        self.assertEqual(signatures.BY_ID["FG-150"].rule, "WEB-WS-PLAINTEXT")

    def test_crypto_rules_report_under_l18(self):
        self.assertEqual(scoring.LAYERS["L18"], "cryptography")
        for n in range(151, 171):
            sig = signatures.BY_ID[f"FG-{n}"]
            with self.subTest(sig=sig.id):
                if sig.stack == "solidity":
                    self.assertEqual(scoring._SIG_LAYER[sig.rule], "L18")
                else:
                    layers = {r.layer for r in scoring.LINE_RULES if r.rule == sig.rule}
                    layers |= {scoring.FILE_RULE_LAYER[sig.rule]} if sig.rule in scoring.FILE_RULE_LAYER else set()
                    self.assertEqual(layers, {"L18"}, sig.rule)

    def test_html_report_renders_dynamic_layer(self):
        # 0.17 dynamic hits carry layer L17; the deductions table used to raise KeyError on it
        f = scoring.Finding("FGX-SWC-129", "MEDIUM", "L17", "Typo", "A.sol", 3, "x =+ y;", "use +=")
        page = scoring.render_html(scoring.ScoreResult("t", "solidity", 92, [f], 1, 3, []))
        self.assertIn("L17 threat intel", page)


class SolidityCryptoTests(unittest.TestCase):
    DOMAIN = ('keccak256(abi.encode(keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"), '
              'keccak256(bytes("V")), {chain}, address(this)))')

    def test_literal_chain_id_is_flagged_even_with_a_chainid_check(self):
        src = f"""pragma solidity 0.8.24;
contract V {{ bytes32 public DOMAIN_SEPARATOR; uint256 id;
    constructor() {{ DOMAIN_SEPARATOR = {self.DOMAIN.format(chain="1")}; id = block.chainid; }}
    function same() external view returns (bool) {{ return block.chainid == id; }} }}"""
        self.assertIn("SOL-EIP712-CACHED-DOMAIN", _sol_rules(src))

    def test_separator_rebuilt_on_fork_is_clean(self):
        src = f"""pragma solidity 0.8.24;
contract V {{ bytes32 private _cachedDomainSeparator; uint256 private _cachedChainId;
    constructor() {{ _cachedChainId = block.chainid; _cachedDomainSeparator = {self.DOMAIN.format(chain="block.chainid")}; }}
    function domainSeparator() public view returns (bytes32) {{
        return block.chainid == _cachedChainId ? _cachedDomainSeparator : {self.DOMAIN.format(chain="block.chainid")}; }} }}"""
        self.assertNotIn("SOL-EIP712-CACHED-DOMAIN", _sol_rules(src))

    def test_string_field_passed_as_precomputed_hash(self):
        src = """pragma solidity 0.8.24;
contract O { bytes32 constant T = keccak256("Order(string memo,uint256 nonce)");
    function h(bytes32 memoHash, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(T, memoHash, nonce)); } }"""
        rules = _sol_rules(src)
        self.assertNotIn("SOL-EIP712-DYNAMIC-UNHASHED", rules)
        self.assertNotIn("SOL-EIP712-TYPEHASH-MISMATCH", rules)

    def test_nested_type_string_counts_primary_fields_only(self):
        src = """pragma solidity 0.8.24;
contract M { bytes32 constant MAIL = keccak256("Mail(Person from,Person to,string contents)Person(string name,address wallet)");
    function h(bytes32 a, bytes32 b, string calldata c) public pure returns (bytes32) {
        return keccak256(abi.encode(MAIL, a, b, keccak256(bytes(c)))); } }"""
        self.assertNotIn("SOL-EIP712-TYPEHASH-MISMATCH", _sol_rules(src))

    def test_erc1271_and_prefixed_digests_are_clean(self):
        src = """pragma solidity 0.8.24;
contract W { address owner;
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        return ecrecover(hash, 27, r, s) == owner ? bytes4(0x1626ba7e) : bytes4(0); } }"""
        rules = _sol_rules(src)
        self.assertNotIn("SOL-SIG-CALLER-DIGEST", rules)
        self.assertNotIn("SOL-SIG-UNPREFIXED-HASH", rules)
        permit = """pragma solidity 0.8.24;
contract P { bytes32 public DOMAIN_SEPARATOR; mapping(address => uint256) public nonces;
    function permit(address o, uint256 v, uint8 v8, bytes32 r, bytes32 s) external {
        bytes32 d = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, keccak256(abi.encode(o, v, nonces[o]++))));
        address who = ecrecover(d, v8, r, s); require(who != address(0) && who == o); } }"""
        self.assertNotIn("SOL-SIG-UNPREFIXED-HASH", _sol_rules(permit))

    def test_digest_recomputed_from_arguments_is_clean(self):
        src = """pragma solidity 0.8.24;
import {ECDSA} from "ECDSA.sol";
contract F { address signer; mapping(address => uint256) nonces;
    function drip(address to, uint256 amount, bytes32 digest, bytes calldata sig) external {
        require(digest == keccak256(abi.encode("\\x19", to, amount, nonces[to]++)), "digest");
        require(ECDSA.recover(digest, sig) == signer); } }"""
        self.assertNotIn("SOL-SIG-CALLER-DIGEST", _sol_rules(src))

    def test_nft_reveal_is_not_commit_reveal(self):
        src = """pragma solidity 0.8.24;
contract N { string base; bool revealed; address owner;
    function reveal(string calldata uri) external { require(msg.sender == owner); base = uri; revealed = true; } }"""
        self.assertNotIn("SOL-COMMIT-NO-SENDER", _sol_rules(src))

    def test_packed_address_amount_leaf_is_52_bytes(self):
        src = """pragma solidity 0.8.24;
import {MerkleProof} from "MerkleProof.sol";
contract A { bytes32 root;
    function claim(address a, uint256 amt, bytes32[] calldata proof) external {
        require(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(a, amt)))); } }"""
        self.assertNotIn("SOL-MERKLE-LEAF-64", _sol_rules(src))
        self.assertIn("SOL-MERKLE-LEAF-64", _sol_rules(src.replace("encodePacked", "encode")))


class WebCryptoTests(unittest.TestCase):
    def test_kdf_floors(self):
        cases = {
            ('const bcrypt = require("bcrypt");\nbcrypt.hash(password, 8);\n', "js"): True,
            ('const bcrypt = require("bcrypt");\nbcrypt.hash(password, 12);\n', "js"): False,
            ('crypto.pbkdf2Sync(pw, salt, 10000, 32, "sha256");\n', "js"): True,
            ('crypto.pbkdf2Sync(pw, salt, 600000, 32, "sha256");\n', "js"): False,
            ('crypto.scryptSync(pw, salt, 32, { N: 1024 });\n', "js"): True,
            ('hashlib.scrypt(pw, salt=s, n=2**14, r=8, p=1)\n', "py"): False,
            ('kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=1_000)\n', "py"): True,
            ('salt = bcrypt.gensalt(rounds=12)\n', "py"): False,
            ('$h = password_hash($pw, PASSWORD_BCRYPT, ["cost" => 6]);\n', "php"): True,
        }
        for (src, lang), weak in cases.items():
            with self.subTest(src=src):
                self.assertEqual("WEB-WEAK-KDF" in _web_rules(src, lang), weak)

    def test_negated_cipher_suites_are_fine(self):
        self.assertNotIn("WEB-LEGACY-TLS", _web_rules('tls.createServer({ ciphers: "HIGH:!aNULL:!eNULL:!RC4:!EXPORT" });\n', "js"))
        self.assertIn("WEB-LEGACY-TLS", _web_rules('tls.createServer({ ciphers: "RC4-SHA:HIGH" });\n', "js"))
        self.assertNotIn("WEB-LEGACY-TLS", _web_rules("ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n", "py"))

    def test_jwt_decode_in_browser_code_or_next_to_verify(self):
        browser = 'import { jwtDecode } from "jwt-decode";\nconst name = jwtDecode(localStorage.idToken).name;\n'
        self.assertNotIn("WEB-JWT-DECODE-ONLY", _web_rules(browser, "js"))
        both = ('function auth(req, res, next) {\n  const h = jwt.decode(req.token, { complete: true }).header;\n'
                '  req.user = jwt.verify(req.token, keys[h.kid], { algorithms: ["RS256"] });\n  next();\n}\n')
        self.assertNotIn("WEB-JWT-DECODE-ONLY", _web_rules(both, "js"))
        self.assertNotIn("WEB-JWT-DECODE-ONLY", _web_rules("claims = jwt.decode(token, key, algorithms=['HS256'])\n", "py"))

    def test_reset_token_digest_is_not_a_password_hash(self):
        src = "digest = hashlib.sha256(password_reset_token.encode()).hexdigest()\n"
        self.assertNotIn("WEB-PASSWORD-FAST-HASH", _web_rules(src, "py"))
        self.assertIn("WEB-PASSWORD-FAST-HASH", _web_rules("digest = hashlib.sha256(password.encode()).hexdigest()\n", "py"))

    def test_library_mode_definitions_are_not_usage(self):
        lib = "CryptoJS.mode.ECB = (function () { return {}; }());\nreturn CryptoJS.mode.CBC;\n"
        rules = _web_rules(lib, "js")
        self.assertFalse(rules & {"WEB-CIPHER-ECB", "WEB-UNAUTHENTICATED-ENCRYPTION"})
        use = 'const ct = CryptoJS.AES.encrypt(msg, key, { mode: CryptoJS.mode.ECB });\n'
        self.assertIn("WEB-CIPHER-ECB", _web_rules(use, "js"))

    def test_ec_curve_key_size_attribute_is_not_rsa(self):
        self.assertNotIn("WEB-RSA-WEAK-KEY", _web_rules("class SECP521R1:\n    key_size = 512\n", "py"))

    def test_gcm_nonce_size_is_not_a_short_token(self):
        src = 'const nonce = crypto.randomBytes(12);\nconst token = crypto.randomBytes(8).toString("hex");\n'
        hits = [f.line for f in scoring.check_text("a.js", src, "js") if f.rule == "WEB-TOKEN-ENTROPY"]
        self.assertEqual(hits, [2])

    def test_mac_in_file_covers_cbc(self):
        src = ('const c = crypto.createCipheriv("aes-256-cbc", key, iv);\n'
               'const tag = crypto.createHmac("sha256", macKey).update(ct).digest();\n')
        self.assertNotIn("WEB-UNAUTHENTICATED-ENCRYPTION", _web_rules(src, "js"))


def _reference_check_text(rel: str, raw: str, lang: str) -> list:
    """check_text as it was in 0.17: file patterns first, then every line through every rule."""
    lines = raw.splitlines()
    if lang == "py":
        clean = [scoring._PY_COMMENT.sub(r"\1", ln) for ln in lines]
    elif lang in ("js", "php"):
        clean = scoring._strip_comments(raw, False, True).splitlines()
    else:
        clean = lines
    out = []
    for rule in scoring.LINE_RULES:
        if lang not in rule.langs or (rule.needs and not rule.needs.search(raw)) or \
                (rule.unless and rule.unless.search(raw)):
            continue
        for i, ln in enumerate(clean, 1):
            if len(ln) <= scoring.LINE_MAX and rule.pattern.search(ln):
                out.append((rule.rule, i))
    return out


class EngineTests(unittest.TestCase):
    def test_line_rules_match_the_reference_engine(self):
        n = 0
        for p, lang in _web_fixtures():
            raw = p.read_text(encoding="utf-8", errors="replace")
            want = _reference_check_text(p.name, raw, lang)
            got = Counter((f.rule, f.line) for f in scoring.check_text(p.name, raw, lang))
            got -= Counter((r, ln) for r, ln, _ in signatures.check_backend(raw, lang) + signatures.missing_security_headers(raw, lang))
            got = [k for k, c in got.items() for _ in range(c) if not k[0].startswith(("URL-", "WEB-CSRF", "WEB-NO-SRI", "WEB-MIXED"))]
            with self.subTest(path=str(p.relative_to(FIXTURES))):
                self.assertEqual(sorted(got), sorted(want))
            n += len(want)
        self.assertGreater(n, 100)

    def test_every_line_rule_hit_has_a_hint_on_its_own_line(self):
        rules = {r.rule for r in scoring.LINE_RULES}
        for p, lang in _web_fixtures():
            raw = p.read_text(encoding="utf-8", errors="replace")
            lines = raw.lower().splitlines()
            for rule, ln in _reference_check_text(p.name, raw, lang):
                hints = scoring.LINE_HINTS.get(rule)
                if rule in rules and hints:
                    with self.subTest(rule=rule, path=p.name, line=ln):
                        self.assertTrue(any(h in lines[ln - 1] for h in hints))

    def test_literal_prefilters_agree_with_the_regex(self):
        pairs = ((signatures.RATE_LIMITER, signatures.limiter_present),
                 (signatures.HEADERS_PRESENT, signatures.headers_present),
                 (web_surface.WEB3_HINT, lambda raw: web_surface.relevant("a.js", raw)))
        samples = [p.read_text(encoding="utf-8", errors="replace") for p, _ in _web_fixtures()]
        samples += ["app.use(RateLimit())", "@limiter.limit('5/minute')", "Throttle", "X-FRAME-OPTIONS: DENY",
                    "const w = new ethers.Wallet(k)", "REACT_APP_PRIVATE_KEY", "nothing here"]
        for pat, fast in pairs:
            for raw in samples:
                self.assertEqual(fast(raw), bool(pat.search(raw)), (pat.pattern[:30], raw[:60]))

    def test_memo_lives_only_inside_a_scan(self):
        self.assertIsNone(scoring._MEMO)
        scoring.score_path(FIXTURES / "ultrapack" / "weak" / "fg151_eip712_cached_domain.sol", config=scoring.ScanConfig())
        self.assertIsNone(scoring._MEMO)
        text = "uint a; // note\n"
        self.assertEqual(scoring.strip_comments(text), scoring._strip_comments(text, True, False))
        self.assertIsNone(scoring._MEMO)

    def test_backend_cheap_first_order_keeps_results(self):
        cases = [
            ('app.post("/login", h);\n', "js", "WEB-RATE-LIMIT", True),
            ('app.post("/login", h);\nconst limiter = rateLimit({});\n', "js", "WEB-RATE-LIMIT", False),
            ('app.get("/o/:id", async (req, res) => res.json(await Order.findById(req.params.id)));\n', "js", "WEB-IDOR", True),
            ('const token = jwt.sign({ sub: id }, KEY);\n', "js", "WEB-JWT-NO-EXPIRY", True),
            ('const token = jwt.sign({ sub: id }, KEY, { expiresIn: "15m" });\n', "js", "WEB-JWT-NO-EXPIRY", False),
        ]
        for src, lang, rule, expect in cases:
            with self.subTest(rule=rule, src=src):
                self.assertEqual(any(r == rule for r, _, _ in signatures.check_backend(src, lang)), expect)


if __name__ == "__main__":
    unittest.main()
