#!/usr/bin/env python3
"""Layer 12: the Web2-to-Web3 bridge validator.

Most real losses in signature-based minting, claims, relayers and bridges do not come from the contract or
from the web app alone. They come from the seam between them: the backend signs whatever the request asks
for, the contract never consumes the nonce the backend put in the payload, the EIP-712 struct the server
signs drifted from the typehash the contract hashes, the RPC answer is trusted before it is final.

This module reads both sides of a repository at once and checks that seam statically:

* Backend (Python, JavaScript/TypeScript): every place a server key signs (EIP-712 typed data, raw
  ``signMessage``) or sends a transaction, the route handler it sits in, whether that handler checks who
  is calling and bounds what it signs, how the key is loaded, logged or shipped to a browser, how
  transaction nonces are allocated, and how receipts and events are trusted.
* Contracts (Solidity): every exposed function that recovers a signer (``ecrecover``, ECDSA,
  ``SignatureChecker``), what the digest is bound to (chain id, contract address, EIP-712 domain), and
  whether it consumes a nonce and enforces a deadline.
* The bridge: each backend signing site is linked to the contract function that verifies it (by the
  EIP-712 primary type, or by the function the backend calls). Typehash fields, domain name/version and
  domain fields are compared across the two languages, and the replay and expiry guarantees are judged on
  the pair, not on one side. Backend contract calls are checked against the ABI the Solidity in the same
  repository actually exposes.

Nothing is executed and nothing is sent anywhere. Every finding carries file and line on the side where
the fix belongs. Findings go into the Layer 10 score under layer L11 (web2-web3 bridge).
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

if __package__:
    from . import scoring
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scoring  # type: ignore

Finding = scoring.Finding
LAYER = "L11"

# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #

WEB3_HINT = re.compile(
    r"\bethers\b|\bweb3\b|\bviem\b|eth_account|eth-account|@wagmi|signTypedData|sign_typed_data|signMessage|"
    r"sign_message|private_?key|privateKey|PRIVATE_KEY|mnemonic|JsonRpcProvider|HTTPProvider|createWalletClient|"
    r"createPublicClient|getTransactionCount|get_transaction_count|ecsign|infura\.io|alchemy\.com|"
    r"(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_\w*(KEY|MNEMONIC|SEED)", re.I)

SIGN_TYPED = re.compile(r"\b_?signTypedData(?:V4)?\s*\(|\bsign_typed_data\s*\(|\bencode_typed_data\s*\(|"
                        r"\bencode_structured_data\s*\(|eth_signTypedData")
SIGN_RAW = re.compile(r"\bsignMessage\s*\(|\bsign_message\s*\(|\bsignHash\s*\(|\bunsafe_sign_hash\s*\(|"
                      r"\bsignDigest\s*\(|\becsign\s*\(|\bsigningKey\.sign\s*\(|\bsign_msg_hash\s*\(")
SEND_TX = re.compile(r"\bsendTransaction\s*\(|\bsend_raw_transaction\s*\(|\bsendRawTransaction\s*\(|"
                     r"\bwriteContract\s*\(|\.transact\s*\(|\.connect\s*\(\s*\w*(wallet|signer|account)\w*\s*\)\s*\.\s*\w+\s*\(",
                     re.I)
SERVER_KEY = re.compile(r"new\s+(ethers\.)?Wallet\s*\(|Wallet\.fromPhrase|fromMnemonic|privateKeyToAccount\s*\(|"
                        r"mnemonicToAccount\s*\(|Account\.from_key\s*\(|from_key\s*\(|Account\.from_mnemonic|"
                        r"PRIVATE_KEY|private_?key|SIGNER_KEY|KmsSigner|AwsKmsSigner|GcpKmsSigner|LocalAccount", re.I)

REQUEST_INPUT = re.compile(r"\brequest\.(args|form|values|json|data|get_json|query_params|path_params|body)\b|"
                           r"\breq\.(body|query|params)\b|\bawait\s+req(uest)?\.json\s*\(|\bctx\.request\.body\b|"
                           r"\$_(GET|POST|REQUEST)\b|:\s*(\w+)Request\b|Body\s*\(|Query\s*\(")
AUTH = re.compile(
    r"login_required|jwt_required|auth_required|permission_required|requires?_auth|require\w*(Auth|User|Session|Login)|"
    r"isAuthenticated|ensureAuth\w*|authenticate\w*|authorize\w*|verifyToken|verify_token|verifyJwt|verify_jwt|"
    r"jwt\.verify|jwt\.decode|passport\.|getServerSession|getSession\s*\(|auth\s*\(\s*\)|current_user|"
    r"get_current_user|req\.user\b|request\.user\b|req\.auth\b|req\.session\b|session\[|withAuth|checkAuth|"
    r"x-api-key|api_key_header|verifyMessage|verify_message|recover_message|recoverMessageAddress|SiweMessage|"
    r"\bsiwe\b|HTTPBearer|OAuth2PasswordBearer|clerk|supabase\.auth|firebase-admin|verifyIdToken", re.I)
BOUNDS = re.compile(r"(?<![=!<>\-])\s(<=|>=|<|>)\s|\bmin\s*\(|\bmax\s*\(|Math\.(min|max)\s*\(|\bclamp\w*\s*\(|"
                    r"\bMAX_\w+|\bLIMIT\w*|\ballow(ed|list)\w*|\bwhitelist\w*|\beligib\w*|\bentitle\w*")

CHAIN_TOKEN = re.compile(r"chain_?id|chainId|block\.chainid|getChainId|get_chain_id|eth\.chain_id", re.I)
CONTRACT_TOKEN = re.compile(r"verifyingContract|verifying_contract|contract_?address|address\(this\)|\.target\b|"
                            r"[cC]ontract\w*\.address\b|getAddress\s*\(\s*\)|"
                            r"\b(MINTER|CONTRACT|VAULT|TOKEN|NFT|COLLECTION|DROP|CLAIM)\w*_ADDRESS\b", re.I)
NONCE_TOKEN = re.compile(r"nonce|salt|\buuid|voucher_?id|request_?id|claim_?id", re.I)
EXPIRY_TOKEN = re.compile(r"deadline|expir|valid_?until|validBefore|valid_before|valid_?after|\bttl\b|expires", re.I)
NONCE_FIELD = re.compile(r"^(nonce|salt|uid|uuid|id|\w*Id|\w*_id|voucher\w*|requestId|claimId)$", re.I)
EXPIRY_FIELD = re.compile(r"deadline|expir|valid_?until|validBefore|valid_before|validAfter|expires", re.I)

# Solidity side
SOL_VERIFY = re.compile(r"\becrecover\s*\(|\bECDSA\s*\.\s*(try)?[Rr]ecover\w*\s*\(|\.\s*(try)?recover\s*\(|"
                        r"\b(try)?[Rr]ecover\s*\(|SignatureChecker\s*\.\s*isValid\w*\s*\(|\bisValidSignatureNow\s*\(|"
                        r"\.\s*isValidSignature\s*\(")
SOL_EIP712 = re.compile(r"_hashTypedDataV4\s*\(|\\x19\\x01|toTypedDataHash\s*\(|_domainSeparatorV4\s*\(|DOMAIN_SEPARATOR")
SOL_REPLAY = re.compile(
    # a used-map marked: used[digest] = true, claimed[id] = 1, executed[h] = block.number
    r"\b\w*(used|claimed|consumed|executed|redeemed|spent|processed|seen|invalidated|filled|minted)\w*"
    r"\s*(\[[^\]]*\]\s*)+(=\s*(true|1|block|type|uint)|\|=)"
    # a nonce map or counter advanced: nonces[a]++, nonces[a] = n + 1, bitmap |= bit, ++nonce
    r"|\b\w*nonces?\w*\s*(\[[^\]]*\]\s*)+(\+\+|\+=|=(?!=)|\|=)|(\+\+)\s*\w*nonces?\w*\b|\b\w*nonce\w*\s*\+\+"
    r"|_use(Checked|Unordered)?Nonce\s*\(|_invalidate\w*\s*\(|_markUsed\w*\s*\(|_consume\w*\s*\(|_setUsed\w*\s*\(",
    re.I)
SOL_DEADLINE = re.compile(r"deadline|expir|validUntil|validBefore|validAfter|expiresAt|expiry", re.I)
SOL_TYPEHASH = re.compile(r"keccak256\s*\(\s*(?:abi\s*\.\s*encodePacked\s*\(\s*)?(?:bytes\s*\(\s*)?\"([A-Za-z_]\w*)\(([^\"()]*)\)")
SOL_TYPEHASH_CONST = re.compile(
    r"bytes32\s+(?:(?:public|private|internal|constant|immutable)\s+)*([A-Za-z_]\w*)\s*=\s*keccak256\s*\(\s*"
    r"(?:abi\s*\.\s*encodePacked\s*\(\s*)?(?:bytes\s*\(\s*)?\"([A-Za-z_]\w*)\(")
SOL_OZ_EIP712 = re.compile(r"\bEIP712\s*\(\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"\s*\)")
SOL_DOMAIN_NAME = re.compile(r"keccak256\s*\(\s*(?:bytes\s*\(\s*)?\"([^\"]+)\"\s*\)?\s*\)")

ETHERS_CONTRACT_API = {
    "connect", "attach", "getAddress", "waitForDeployment", "deployed", "on", "off", "once", "queryFilter", "filters",
    "interface", "target", "runner", "getFunction", "getEvent", "estimateGas", "populateTransaction", "callStatic",
    "functions", "methods", "events", "address", "removeAllListeners", "listeners", "listenerCount", "encodeABI",
    "call", "send", "staticCall", "getDeployedCode", "deploymentTransaction", "caller", "constructor", "then",
    "transact", "build_transaction", "estimate_gas", "get_logs", "create_filter", "get", "set", "read", "write",
    "simulate", "watchEvent", "createEventFilter", "abi", "bytecode", "toString", "toJSON", "keys", "values",
}

# Standard token / oracle / pool functions: a backend calling them usually talks to a contract outside this repo.
STANDARD_NAMES = {
    "transfer", "transferFrom", "approve", "balanceOf", "allowance", "totalSupply", "decimals", "symbol", "name",
    "ownerOf", "safeTransferFrom", "setApprovalForAll", "isApprovedForAll", "getApproved", "tokenURI", "permit",
    "nonces", "DOMAIN_SEPARATOR", "deposit", "withdraw", "mint", "burn", "owner", "getReserves", "latestRoundData",
    "multicall", "eip712Domain", "supportsInterface", "safeBatchTransferFrom", "uri", "balanceOfBatch", "redeem",
    "convertToAssets", "convertToShares", "previewDeposit", "previewRedeem", "asset", "totalAssets",
}

CLIENT_DIRS = {"components", "frontend", "client", "public", "web", "ui", "pages", "views", "static", "www"}
CLIENT_EXT = {".jsx", ".tsx", ".vue", ".svelte", ".html", ".htm"}

LOG_CALL = re.compile(r"console\.(log|info|debug|warn|error|trace)\s*\(|(?<![\w.])print\s*\(|\blogger\.\w+\s*\(|"
                      r"\blogging\.\w+\s*\(|\blog\.(info|debug|warn|error)\s*\(|\bres\.(json|send)\s*\(|\bjsonify\s*\(")
KEY_MATERIAL = re.compile(r"private_?key|privateKey|PRIVATE_KEY|mnemonic|seed_?phrase|signingKey|\.key\.hex\s*\(|"
                          r"\b(acct|account|signer|wallet)\.(key|_private_key|privateKey)\b", re.I)
_KEY_NAMES = r"(private_?key|privateKey|mnemonic|seed_?phrase|secret_?key|secretKey)"
KEY_FROM_REQUEST = re.compile(
    r"\b(req|request|ctx\.request)\s*\.\s*(body|query|params|json|form|args|values|data|get_json\s*\(\s*\))\s*"
    r"(\.\s*|\[\s*['\"]|\.\s*get\s*\(\s*['\"])" + _KEY_NAMES +
    r"|\{[^}]*\b" + _KEY_NAMES + r"\b[^}]*\}\s*=\s*(await\s+)?(req|request)\s*\." +
    r"|\b" + _KEY_NAMES + r"\w*\s*[:=]\s*(await\s+)?(req|request)\s*\.\s*(body|query|params|json|form|args)\b", re.I)
CLIENT_ENV_KEY = re.compile(r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_\w*"
                            r"(PRIVATE_?KEY|MNEMONIC|SEED|SIGNER_?KEY|DEPLOYER_?KEY|WALLET_?KEY)\w*")
CLIENT_WALLET = re.compile(r"new\s+(ethers\.)?Wallet\s*\(|privateKeyToAccount\s*\(|mnemonicToAccount\s*\(|"
                           r"Wallet\.fromPhrase\s*\(|Wallet\.fromMnemonic\s*\(|HDNodeWallet\.fromPhrase\s*\(")
MNEMONIC_LITERAL = re.compile(r"(mnemonic|seed|phrase|recovery)\w*['\"]?\s*[:=(]\s*['\"](?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}['\"]|"
                              r"fromPhrase\s*\(\s*['\"](?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}['\"]", re.I)
RPC_KEY = re.compile(r"(infura\.io/v3/|alchemy\.com/v2/|alchemyapi\.io/v2/|quiknode\.pro/|ankr\.com/[a-z_]+/|"
                     r"chainstack\.com/|blastapi\.io/|getblock\.io/|drpc\.org/\w+/)[A-Za-z0-9_-]{16,}", re.I)
TX_COUNT = re.compile(r"\bgetTransactionCount\s*\(|\bget_transaction_count\s*\(")
MANUAL_NONCE = re.compile(r"(?<![\w.])['\"]?nonce['\"]?\s*:|\bnonce\s*=\s*(?!None)")
NONCE_LOCK = re.compile(r"\bLock\b|Mutex|Semaphore|redlock|async-mutex|p-queue|PQueue|NonceManager|threading\.Lock|"
                        r"asyncio\.Lock|with_lock|FOR UPDATE|\bqueue\b|bullmq|SELECT[^\n]*FOR\s+UPDATE", re.I)
WEAK_NONCE = re.compile(r"\bnonce\w*['\"]?\s*[:=]\s*[^\n;,]*(Date\.now\s*\(|time\.time(_ns)?\s*\(|Math\.random\s*\(|"
                        r"random\.(randint|random|getrandbits)\s*\(|performance\.now\s*\()", re.I)
COUNTER_NONCE = re.compile(r"^(?:let|var|export\s+let)\s+(\w*nonce\w*)\s*=\s*\d+|^(\w*nonce\w*)\s*=\s*\d+\s*$", re.I)
RECEIPT_WAIT = re.compile(r"\bwait_for_transaction_receipt\s*\(|\bwaitForTransactionReceipt\s*\(|"
                          r"\bgetTransactionReceipt\s*\(|\bget_transaction_receipt\s*\(")
RECEIPT_STATUS = re.compile(r"\w*receipt\w*\s*(\.\s*status|\[\s*['\"]status['\"]\s*\])|"
                            r"\.status\s*(===?|!==?)\s*(1|0|['\"](success|reverted)['\"])|status\s*==\s*[01]\b|"
                            r"['\"]status['\"]\s*\]\s*(==|!=)|CALL_EXCEPTION|\bstatus\s*[!=]==?\s*['\"](success|reverted)", re.I)
EVENT_SOURCE = re.compile(r"\.\s*on\s*\(\s*['\"][A-Z]\w*['\"]|\bwatchContractEvent\s*\(|\bwatchEvent\s*\(|"
                          r"\bcreate_filter\s*\(|\bcreateEventFilter\s*\(|\bget_logs\s*\(|\bgetLogs\s*\(|"
                          r"\bgetPastEvents\s*\(|\bqueryFilter\s*\(|eth_getLogs")
FINALITY = re.compile(r"confirmations?|CONFIRMATIONS|blockConfirmations|finalized|['\"]safe['\"]|reorg|"
                      r"REORG|FINALITY|finality|block_number\s*-|blockNumber\s*-", re.I)


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #


@dataclass
class TypedStruct:
    name: str
    fields: list[tuple[str, str]]  # (type, name)
    file: str
    line: int

    @property
    def signature(self) -> str:
        return f"{self.name}(" + ",".join(f"{t} {n}" for t, n in self.fields) + ")"

    def normalized(self) -> tuple:
        return tuple((_norm_type(t), n) for t, n in self.fields)


@dataclass
class Domain:
    fields: dict[str, str]  # chainId / verifyingContract / name / version / salt -> value text
    file: str
    line: int

    def literal(self, key: str) -> str | None:
        v = self.fields.get(key, "").strip()
        m = re.fullmatch(r"['\"`]([^'\"`]*)['\"`]", v)
        return m.group(1) if m else None


@dataclass
class Handler:
    route: str
    start: int  # offsets into the source
    end: int
    line: int
    header: str  # decorators / middleware text


@dataclass
class SignSite:
    file: str
    line: int
    kind: str  # typed | raw | send
    client: bool
    server_key: bool
    struct: TypedStruct | None = None
    domain: Domain | None = None
    handler: Handler | None = None
    has_chain: bool = False
    has_contract: bool = False
    has_nonce: bool = False
    has_expiry: bool = False
    has_input: bool = False
    has_auth: bool = False
    has_bounds: bool = False
    window: str = ""


@dataclass
class VerifySite:
    file: str
    line: int
    contract: str
    function: str
    method: str  # eip712 | raw
    chain_bound: bool
    contract_bound: bool
    replay_guard: bool
    deadline: bool
    typehash: TypedStruct | None = None
    domain_name: str | None = None
    domain_version: str | None = None
    domain_fields: list[str] | None = None  # from a hand-written EIP712Domain typehash; None for OZ EIP712


@dataclass
class BridgeLink:
    sign: SignSite
    verify: VerifySite | None
    status: str  # bound | drift | replayable | oracle | unbound | unlinked
    notes: list[str] = field(default_factory=list)


@dataclass
class BridgeReport:
    findings: list[Finding] = field(default_factory=list)
    signs: list[SignSite] = field(default_factory=list)
    verifies: list[VerifySite] = field(default_factory=list)
    links: list[BridgeLink] = field(default_factory=list)
    calls: int = 0  # backend contract calls checked against the local ABI

    @property
    def empty(self) -> bool:
        return not (self.signs or self.verifies or self.findings)

    def as_dict(self) -> dict:
        def site(s: SignSite) -> dict:
            return {"file": s.file, "line": s.line, "kind": s.kind, "client": s.client,
                    "struct": s.struct.signature if s.struct else None,
                    "route": s.handler.route if s.handler else None,
                    "auth": s.has_auth, "request_input": s.has_input, "bounded": s.has_bounds,
                    "chain_id": s.has_chain, "contract": s.has_contract, "nonce": s.has_nonce, "expiry": s.has_expiry}

        def ver(v: VerifySite) -> dict:
            d = asdict(v)
            d["typehash"] = v.typehash.signature if v.typehash else None
            return d

        return {
            "links": [{"sign": site(l.sign), "verify": ver(l.verify) if l.verify else None, "status": l.status,
                       "notes": l.notes} for l in self.links],
            "unlinked_verifiers": [ver(v) for v in self.verifies if not any(l.verify is v for l in self.links)],
            "contract_calls_checked": self.calls,
            "findings": len(self.findings),
        }


def _norm_type(t: str) -> str:
    t = t.strip()
    t = re.sub(r"^uint(?=\[|$)", "uint256", t)
    t = re.sub(r"^int(?=\[|$)", "int256", t)
    return t


# --------------------------------------------------------------------------- #
# Source helpers
# --------------------------------------------------------------------------- #


def clean_python(text: str, blank_strings: bool = True) -> str:
    """``#`` comments blanked, and string contents too when asked. Offsets and newlines are kept."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c in "\"'":
            q = text[i:i + 3] if text[i:i + 3] in ('"""', "'''") else c
            j = i + len(q)
            while j < n and not text.startswith(q, j) and (len(q) == 3 or text[j] != "\n"):
                j += 2 if text[j] == "\\" else 1
            if blank_strings:
                for k in range(i + len(q), min(j, n)):
                    if out[k] != "\n":
                        out[k] = " "
            i = j + len(q)
        else:
            i += 1
    return "".join(out)


class _Src:
    """A backend file: raw text, text with comments removed (strings kept) and a structural copy."""

    def __init__(self, rel: str, raw: str):
        self.rel = rel
        self.raw = raw
        self.lines = raw.splitlines()
        self.py = rel.lower().endswith(".py")
        if self.py:
            self.keep = clean_python(raw, blank_strings=False)
            self.struct = clean_python(raw, blank_strings=True)
        else:
            self.keep = scoring.strip_comments(raw, blank_strings=False)
            self.struct = scoring.strip_comments(raw, blank_strings=True)
        self.client = is_client(rel, raw)
        self.server_key = bool(SERVER_KEY.search(self.keep)) and not self.client
        self.handlers = python_handlers(self) if self.py else js_handlers(self)

    def line(self, offset: int) -> int:
        return scoring.line_of(self.raw, offset)

    def snip(self, line: int) -> str:
        return scoring.snippet(self.lines, line)

    def handler_at(self, offset: int) -> Handler | None:
        best = None
        for h in self.handlers:
            if h.start <= offset <= h.end and (best is None or h.start >= best.start):
                best = h
        return best


def is_client(rel: str, raw: str) -> bool:
    p = Path(rel)
    parts = {x.lower() for x in p.parts[:-1]}
    if p.suffix.lower() in CLIENT_EXT:
        return True
    if re.search(r"^\s*['\"]use client['\"]", raw[:400], re.M):
        return True
    if "api" in parts or "server" in parts or "backend" in parts:
        return False
    return bool(parts & CLIENT_DIRS) and p.suffix.lower() != ".py"


PY_ROUTE = re.compile(r"^[ \t]*@[\w.]+\.(route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*(?:['\"]([^'\"]*)['\"])?",
                      re.M)
JS_ROUTE = re.compile(r"\b(app|router|server|api|fastify|\w+Router|\w+Routes)\s*\.\s*(get|post|put|patch|delete|all)\s*\(")
NEXT_ROUTE = re.compile(r"export\s+(?:default\s+)?(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE|GET|handler)\s*\(|"
                        r"export\s+const\s+(POST|PUT|PATCH|DELETE|GET)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>")


def python_handlers(src: _Src) -> list[Handler]:
    out: list[Handler] = []
    lines = src.struct.split("\n")
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln) + 1)
    for m in PY_ROUTE.finditer(src.struct):
        rm = re.match(r"[^(]*\(\s*['\"]([^'\"]*)", src.keep[m.start():m.end() + 200])
        route = rm.group(1) if rm else "?"
        i = src.struct.count("\n", 0, m.start())
        deco_start = i
        while deco_start > 0 and lines[deco_start - 1].lstrip().startswith("@"):
            deco_start -= 1
        j = i
        while j < len(lines) and not re.match(r"\s*(async\s+)?def\s", lines[j]):
            j += 1
        if j >= len(lines):
            continue
        indent = len(lines[j]) - len(lines[j].lstrip())
        k = j + 1
        # skip the rest of a multi-line signature
        while k < len(lines) and not lines[j:k][-1].rstrip().endswith(":") and k - j < 20:
            k += 1
        end = k
        while end < len(lines):
            ln = lines[end]
            if ln.strip() and len(ln) - len(ln.lstrip()) <= indent:
                break
            end += 1
        header = "\n".join(src.keep.split("\n")[deco_start:j + 1])
        out.append(Handler(route, offsets[deco_start], offsets[end] - 1, deco_start + 1, header))
    return out


def js_handlers(src: _Src) -> list[Handler]:
    out: list[Handler] = []
    s = src.struct
    for m in JS_ROUTE.finditer(s):
        open_i = m.end() - 1
        close_i = scoring.match_close(s, open_i, "(", ")")
        args = src.keep[open_i:close_i]
        rm = re.match(r"\(\s*['\"`]([^'\"`]*)['\"`]", args)
        route = f"{m.group(2).upper()} {rm.group(1) if rm else '?'}"
        # middleware is everything before the last function argument
        last_fn = max(args.rfind("=>"), args.rfind("function"))
        header = args[:last_fn] if last_fn > 0 else ""
        out.append(Handler(route, open_i, close_i, src.line(m.start()), header))
    for m in NEXT_ROUTE.finditer(s):
        bm = re.compile(r"\{").search(s, m.end())
        if not bm:
            continue
        # function form: the body starts after the parameter list
        start = bm.start()
        if m.group(1):
            p_open = s.find("(", m.end() - 1)
            p_close = scoring.match_close(s, p_open, "(", ")")
            bm2 = re.compile(r"\{").search(s, p_close)
            start = bm2.start() if bm2 else start
        end = scoring.match_close(s, start)
        name = m.group(1) or m.group(2)
        out.append(Handler(f"{name if name != 'handler' else 'ANY'} (route file)", m.start(), end, src.line(m.start()), ""))
    return out


# --------------------------------------------------------------------------- #
# Backend: EIP-712 structs and domains
# --------------------------------------------------------------------------- #

STRUCT_HEAD = re.compile(r"['\"]?([A-Z]\w*)['\"]?\s*:\s*\[")
FIELD_NT = re.compile(r"\{\s*['\"]?name['\"]?\s*:\s*['\"](\w+)['\"]\s*,\s*['\"]?type['\"]?\s*:\s*['\"]([\w\[\]]+)['\"]\s*,?\s*\}")
FIELD_TN = re.compile(r"\{\s*['\"]?type['\"]?\s*:\s*['\"]([\w\[\]]+)['\"]\s*,\s*['\"]?name['\"]?\s*:\s*['\"](\w+)['\"]\s*,?\s*\}")
DOMAIN_HEAD = re.compile(r"['\"]?\w*domain\w*['\"]?\s*[:=]\s*(?:dict\s*\(|\{)", re.I)
DOMAIN_KEY = re.compile(r"['\"]?(name|version|chainId|chain_id|verifyingContract|verifying_contract|salt)['\"]?\s*[:=]\s*"
                        r"([^,\n})]+)")
PRIMARY = re.compile(r"['\"]?primary_?[Tt]ype['\"]?\s*[:=]\s*['\"](\w+)['\"]")


def backend_structs(src: _Src) -> list[TypedStruct]:
    out = []
    for m in STRUCT_HEAD.finditer(src.keep):
        open_i = m.end() - 1
        if src.struct[open_i] != "[":
            continue
        close_i = scoring.match_close(src.struct, open_i, "[", "]")
        body = src.keep[open_i + 1:close_i]
        items = [(t, n) for n, t in FIELD_NT.findall(body)] or [(t, n) for t, n in FIELD_TN.findall(body)]
        if not items:
            continue
        # every element of the list must be a {name, type} pair
        if len(items) != body.count("{"):
            continue
        name = re.match(r"['\"]?(\w+)", src.keep[m.start():m.end()]).group(1)
        out.append(TypedStruct(name, items, src.rel, src.line(m.start())))
    return out


def backend_domains(src: _Src) -> list[Domain]:
    out = []
    for m in DOMAIN_HEAD.finditer(src.keep):
        if src.struct[m.end() - 1] not in "{(":
            continue
        open_c = src.struct[m.end() - 1]
        close_i = scoring.match_close(src.struct, m.end() - 1, open_c, "}" if open_c == "{" else ")")
        body = src.keep[m.end():close_i]
        fields = {}
        for k, v in DOMAIN_KEY.findall(body):
            k = {"chain_id": "chainId", "verifying_contract": "verifyingContract"}.get(k, k)
            fields.setdefault(k, v.strip())
        # shorthand properties in JS: { name, version, chainId, verifyingContract }
        for k in re.findall(r"(?<![\w.:'\"])(chainId|verifyingContract|name|version|salt)\s*(?=[,}\n])", body):
            fields.setdefault(k, k)
        if fields and ({"chainId", "verifyingContract"} & set(fields) or {"name", "version"} <= set(fields)):
            out.append(Domain(fields, src.rel, src.line(m.start())))
    return out


def _pick_struct(structs: list[TypedStruct], primary: str | None, line: int) -> TypedStruct | None:
    cands = [s for s in structs if s.name != "EIP712Domain"]
    if primary:
        for s in cands:
            if s.name == primary:
                return s
    referenced = {t.rstrip("[]") for s in cands for t, _ in s.fields}
    top = [s for s in cands if s.name not in referenced] or cands
    if not top:
        return None
    before = [s for s in top if s.line <= line]
    return max(before, key=lambda s: s.line) if before else min(top, key=lambda s: s.line)


def _pick_domain(domains: list[Domain], line: int) -> Domain | None:
    if not domains:
        return None
    before = [d for d in domains if d.line <= line]
    return max(before, key=lambda d: d.line) if before else min(domains, key=lambda d: d.line)


# --------------------------------------------------------------------------- #
# Backend scan
# --------------------------------------------------------------------------- #


def _window(src: _Src, offset: int, handler: Handler | None) -> str:
    if handler:
        return src.keep[handler.start:handler.end + 1]
    line = src.line(offset)
    return "\n".join(src.keep.split("\n")[max(0, line - 26):line + 25])


def scan_backend(src: _Src) -> tuple[list[SignSite], list[Finding]]:
    sites: list[SignSite] = []
    out: list[Finding] = []

    def add(rule, sev, title, line, mitigation):
        out.append(Finding(rule, sev, LAYER, title, src.rel, line, src.snip(line), mitigation))

    structs = backend_structs(src)
    domains = backend_domains(src)
    seen_lines: set[tuple[str, int]] = set()
    for kind, pat in (("typed", SIGN_TYPED), ("raw", SIGN_RAW), ("send", SEND_TX)):
        for m in pat.finditer(src.struct):
            line = src.line(m.start())
            if (kind, line) in seen_lines or any(k != kind and ln == line for k, ln in seen_lines):
                continue
            seen_lines.add((kind, line))
            h = src.handler_at(m.start())
            win = _window(src, m.start(), h)
            site = SignSite(src.rel, line, kind, src.client, src.server_key, handler=h, window=win)
            if kind == "typed":
                pm = PRIMARY.search(win)
                site.struct = _pick_struct(structs, pm.group(1) if pm else None, line)
                site.domain = _pick_domain(domains, line)
                if site.domain:
                    site.has_chain = "chainId" in site.domain.fields
                    site.has_contract = "verifyingContract" in site.domain.fields or "salt" in site.domain.fields
                if site.struct:
                    site.has_nonce = any(NONCE_FIELD.match(n) for _, n in site.struct.fields)
                    site.has_expiry = any(EXPIRY_FIELD.search(n) for _, n in site.struct.fields)
            else:
                site.has_chain = bool(CHAIN_TOKEN.search(win))
                site.has_contract = bool(CONTRACT_TOKEN.search(win))
                site.has_nonce = bool(NONCE_TOKEN.search(win))
                site.has_expiry = bool(EXPIRY_TOKEN.search(win))
            if h:
                body = src.keep[h.start:h.end + 1]
                site.has_input = bool(REQUEST_INPUT.search(body))
                site.has_auth = bool(AUTH.search(h.header) or AUTH.search(body))
                site.has_bounds = bool(BOUNDS.search(src.struct[h.start:h.end + 1])
                                       or scoring.VALIDATION_LIBS.search(src.keep))
            sites.append(site)

            if site.server_key and h and site.has_input:
                what = "signs" if kind != "send" else "sends a transaction with"
                if not site.has_auth:
                    rule = "BRIDGE-SIGNING-ORACLE" if kind != "send" else "BRIDGE-OPEN-RELAYER"
                    add(rule, "CRITICAL",
                        f"Route `{h.route}` signs with the server key for any caller" if kind != "send"
                        else f"Route `{h.route}` spends the server key's gas for any caller",
                        line, "Authenticate the caller before the key is touched (session, JWT, SIWE), derive the "
                        "recipient from the authenticated identity, and rate-limit the route. A public signer is a "
                        "mint button for the whole internet.")
                elif not site.has_bounds:
                    add("BRIDGE-SIGNED-INPUT-UNCHECKED", "HIGH",
                        f"Route `{h.route}` {what} request values without bounds", line,
                        "Validate every signed field against a schema and the caller's entitlement (max amount, "
                        "allowed token ids, recipient == authenticated user) before signing.")

    for i, ln in enumerate(src.keep.split("\n"), 1):
        if len(ln) > 4000:
            continue
        if KEY_FROM_REQUEST.search(ln):
            add("BRIDGE-KEY-FROM-REQUEST", "CRITICAL", "Private key or mnemonic read from the request", i,
                "Never accept key material over HTTP. Keep the key in a KMS/HSM or the server environment.")
        if LOG_CALL.search(ln) and KEY_MATERIAL.search(ln):
            add("BRIDGE-KEY-LOGGED", "HIGH", "Key material written to a log or response", i,
                "Remove it; log the signer address instead. Rotate the key if this ever ran in production.")
        if CLIENT_ENV_KEY.search(ln):
            add("BRIDGE-KEY-CLIENT", "CRITICAL", "Signing key exposed through a public build variable", i,
                "Public env prefixes are inlined into the browser bundle. Move signing to the server and "
                "rotate the key.")
        elif src.client and CLIENT_WALLET.search(ln):
            add("BRIDGE-KEY-CLIENT", "CRITICAL", "Wallet built from a private key in browser code", i,
                "Browser code must use the user's wallet (EIP-1193 provider); a key shipped to the client is public.")
        if MNEMONIC_LITERAL.search(ln):
            add("BRIDGE-MNEMONIC-LITERAL", "CRITICAL", "Seed phrase in source", i,
                "Move it out of the repository, treat every derived account as compromised and drain them to new keys.")
        if RPC_KEY.search(ln) and not re.search(r"\$\{|\{\w+\}|%s|os\.environ|process\.env", ln):
            sev = "MEDIUM" if src.client else "LOW"
            add("BRIDGE-RPC-KEY", sev, "RPC provider key embedded in a URL" + (" shipped to browsers" if src.client else ""),
                i, "Read the RPC URL from the environment; for browser traffic proxy through your backend or "
                "lock the key to allowed origins and methods.")
        if WEAK_NONCE.search(ln):
            add("BRIDGE-WEAK-NONCE", "MEDIUM", "Signature nonce from a clock or non-crypto random", i,
                "Allocate nonces from the contract (`nonces(user)`) or a persistent counter, or use 32 random bytes "
                "from `secrets`/`crypto.randomBytes` with an on-chain used-map.")
        cm = COUNTER_NONCE.match(ln)
        if cm:
            name = cm.group(1) or cm.group(2)
            if re.search(rf"\b{re.escape(name)}\s*(\+\+|\+=)|(\+\+)\s*{re.escape(name)}\b", src.keep):
                add("BRIDGE-WEAK-NONCE", "MEDIUM", f"Nonce counter `{name}` lives in process memory", i,
                    "It restarts at the initial value after a deploy or crash and differs per worker; read the "
                    "nonce from the contract or a database row.")

    if src.server_key and not src.client:
        tc = list(TX_COUNT.finditer(src.struct))
        if tc and MANUAL_NONCE.search(src.struct) and not NONCE_LOCK.search(src.keep):
            for m in tc:
                ln = src.line(m.start())
                if "pending" in src.lines[ln - 1].lower():
                    continue
                add("BRIDGE-TX-NONCE-RACE", "MEDIUM", "Transaction nonce read and set by hand without a lock", ln,
                    "Two concurrent requests get the same nonce and one transaction is dropped or replaced. Use a "
                    "nonce manager / single queue per key, or read the `pending` count under a lock.")
    if not src.client:
        rw = list(RECEIPT_WAIT.finditer(src.struct))
        if rw and not RECEIPT_STATUS.search(src.keep):
            ln = src.line(rw[0].start())
            add("BRIDGE-RECEIPT-STATUS", "HIGH", "Transaction receipt used without checking `status`", ln,
                "A mined transaction can have reverted. Check `receipt.status == 1` (`'success'` in viem) before "
                "crediting, marking paid or releasing anything off-chain.")
        ev = EVENT_SOURCE.search(src.keep)
        if ev and not FINALITY.search(src.keep):
            ln = src.line(ev.start())
            add("BRIDGE-REORG", "MEDIUM", "Chain events acted on with no confirmation depth", ln,
                "Wait for N confirmations (or the `finalized` block tag) before crediting deposits or "
                "triggering off-chain actions; reorged events disappear.")
    return sites, out


# --------------------------------------------------------------------------- #
# Backend contract calls (ABI drift)
# --------------------------------------------------------------------------- #

CALL_FORMS = (
    re.compile(r"\.\s*functions\s*\.\s*([A-Za-z_]\w*)\s*\("),
    re.compile(r"\.\s*methods\s*\.\s*([A-Za-z_]\w*)\s*\("),
    re.compile(r"\b\w*[Cc]ontract\w*\s*\.\s*([A-Za-z_]\w*)\s*\("),
    re.compile(r"\.\s*connect\s*\([^()]*\)\s*\.\s*([A-Za-z_]\w*)\s*\("),
)
VIEM_CALL = re.compile(r"functionName\s*:\s*['\"](\w+)['\"]")
ENCODE_CALL = re.compile(r"encodeFunctionData\s*\(\s*['\"](\w+)['\"]\s*,\s*\[")


def _split_args(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def backend_calls(src: _Src) -> list[tuple[str, int | None, bool, int]]:
    """(function name, argument count or None, last argument may be an overrides object, line)."""
    out = []
    s = src.struct
    for pat in CALL_FORMS:
        for m in pat.finditer(s):
            name = m.group(1)
            if name in ETHERS_CONTRACT_API:
                continue
            close = scoring.match_close(s, m.end() - 1, "(", ")")
            args = _split_args(src.keep[m.end():close])
            if any(a.startswith("...") or a.startswith("*") for a in args):
                n = None
            else:
                n = len(args)
            overrides = bool(args) and args[-1].lstrip().startswith("{")
            out.append((name, n, overrides, src.line(m.start())))
    for m in VIEM_CALL.finditer(src.keep):
        start = src.struct.rfind("{", 0, m.start())
        end = scoring.match_close(src.struct, start) if start >= 0 else m.end()
        obj = src.keep[start:end]
        am = re.search(r"\bargs\s*:\s*\[", obj)
        n = None
        if am:
            a_open = start + am.end() - 1
            a_close = scoring.match_close(src.struct, a_open, "[", "]")
            n = len(_split_args(src.keep[a_open + 1:a_close]))
        elif re.search(r"\bargs\s*[:,}]", obj):
            n = None
        else:
            n = 0
        out.append((m.group(1), n, False, src.line(m.start())))
    for m in ENCODE_CALL.finditer(src.keep):
        a_open = m.end() - 1
        a_close = scoring.match_close(src.struct, a_open, "[", "]")
        out.append((m.group(1), len(_split_args(src.keep[a_open + 1:a_close])), False, src.line(m.start())))
    return out


# --------------------------------------------------------------------------- #
# Solidity side
# --------------------------------------------------------------------------- #


@dataclass
class _SolSrc:
    rel: str
    raw: str
    keep: str
    clean: str
    contracts: list


def _sol_src(rel: str, raw: str) -> _SolSrc:
    clean = scoring.strip_comments(raw)
    return _SolSrc(rel, raw, scoring.strip_comments(raw, blank_strings=False), clean, scoring.parse_solidity(clean))


def _reach(ss: _SolSrc, c, fn) -> tuple[str, str, list]:
    """Clean and string-keeping text of ``fn`` plus every internal function and modifier it reaches in ``c``."""
    seen = {fn.name}
    todo = [fn]
    parts_c, parts_k, reached = [], [], []
    by_name: dict[str, list] = {}
    for f in c.functions:
        by_name.setdefault(f.name, []).append(f)
    while todo:
        f = todo.pop()
        reached.append(f)
        parts_c.append(ss.clean[f.body_start:f.body_end + 1])
        parts_k.append(ss.keep[f.body_start:f.body_end + 1])
        names = set(re.findall(r"(?<![\w.$])([A-Za-z_]\w*)\s*\(", parts_c[-1])) | set(f.modifiers)
        for n in names:
            for g in by_name.get(n, []):
                if g.name not in seen and g.kind in ("function", "modifier"):
                    seen.add(g.name)
                    todo.append(g)
    return "\n".join(parts_c), "\n".join(parts_k), reached


def scan_solidity(ss: _SolSrc) -> tuple[list[VerifySite], list[Finding], dict[str, TypedStruct], set[str]]:
    sites: list[VerifySite] = []
    out: list[Finding] = []
    structs: dict[str, TypedStruct] = {}
    lines = ss.raw.splitlines()

    for m in SOL_TYPEHASH.finditer(ss.keep):
        name, body = m.group(1), m.group(2)
        fields = []
        for part in [p.strip() for p in body.split(",") if p.strip()]:
            bits = part.split()
            if len(bits) >= 2:
                fields.append((bits[0], bits[-1]))
        structs.setdefault(name, TypedStruct(name, fields, ss.rel, scoring.line_of(ss.raw, m.start())))
    consts = {m.group(1): m.group(2) for m in SOL_TYPEHASH_CONST.finditer(ss.keep)}

    for c in ss.contracts:
        if c.kind in ("interface", "library"):
            continue
        ctext_k = ss.keep[c.start:c.end + 1]
        oz = SOL_OZ_EIP712.search(ctext_k) or SOL_OZ_EIP712.search(ss.keep[:c.start + 400])
        dom = structs.get("EIP712Domain")
        for fn in c.functions:
            if not (fn.exposed and fn.state_changing):
                continue
            body_c, body_k, reached = _reach(ss, c, fn)
            if not SOL_VERIFY.search(body_c):
                continue
            eip712 = bool(SOL_EIP712.search(body_k))
            chain_bound = contract_bound = False
            dom_fields = None
            if eip712:
                if oz:
                    chain_bound = contract_bound = True
                elif dom:
                    dom_fields = [n for _, n in dom.fields]
                    chain_bound = "chainId" in dom_fields
                    contract_bound = "verifyingContract" in dom_fields or "salt" in dom_fields
                else:
                    chain_bound = bool(re.search(r"block\s*\.\s*chainid", ctext_k))
                    contract_bound = bool(re.search(r"address\s*\(\s*this\s*\)", ctext_k))
            else:
                chain_bound = bool(re.search(r"block\s*\.\s*chainid", body_c))
                contract_bound = bool(re.search(r"address\s*\(\s*this\s*\)", body_c))
            replay = bool(SOL_REPLAY.search(body_c))
            deadline = bool(re.search(r"block\s*\.\s*timestamp", body_c)) and bool(SOL_DEADLINE.search(body_c))
            typehash = None
            for const, sname in consts.items():
                if sname != "EIP712Domain" and re.search(rf"\b{re.escape(const)}\b", body_c):
                    typehash = structs.get(sname)
                    break
            if typehash is None and eip712:
                for th in SOL_TYPEHASH.finditer(body_k):
                    if th.group(1) != "EIP712Domain":
                        typehash = structs.get(th.group(1))
                        break
            if typehash is None and eip712:
                cands = [s for n, s in structs.items() if n != "EIP712Domain"]
                if len(cands) == 1:
                    typehash = cands[0]
            dname = dver = None
            if oz:
                dname, dver = oz.group(1), oz.group(2)
            elif dom:
                lits = SOL_DOMAIN_NAME.findall(ctext_k)
                lits = [x for x in lits if "(" not in x]
                if lits:
                    dname = lits[0]
                    dver = lits[1] if len(lits) > 1 else None
            site = VerifySite(ss.rel, fn.line, c.name, fn.name, "eip712" if eip712 else "raw", chain_bound,
                              contract_bound, replay, deadline, typehash, dname, dver, dom_fields)
            sites.append(site)

            def add(rule, sev, title, mitigation, line=fn.line):
                out.append(Finding(rule, sev, LAYER, title, ss.rel, line, scoring.snippet(lines, line), mitigation,
                                   contract=c.name))

            if not (chain_bound and contract_bound):
                missing = " and ".join(x for x, ok in (("chain id", chain_bound), ("contract address", contract_bound))
                                       if not ok)
                add("BRIDGE-SIG-NO-DOMAIN", "HIGH",
                    f"`{c.name}.{fn.name}` accepts signatures not bound to the {missing}",
                    "Hash with EIP-712 (OpenZeppelin `EIP712` + `_hashTypedDataV4`): the domain carries "
                    "`block.chainid` and `address(this)`, so a signature for one chain or deployment cannot "
                    "be replayed on another.")
            if "ecrecover" in body_c and not re.search(r"address\s*\(\s*0\s*\)", body_c):
                add("BRIDGE-RAW-ECRECOVER", "MEDIUM", f"Bare `ecrecover` in `{c.name}.{fn.name}`",
                    "`ecrecover` returns address(0) on a bad signature and accepts malleable `s` values. Use "
                    "OpenZeppelin `ECDSA.recover` (or check `signer != address(0)` and `s` in the lower half order).")
            for pm in re.finditer(r"abi\s*\.\s*encodePacked\s*\(", body_c):
                close = scoring.match_close(body_c, pm.end() - 1, "(", ")")
                args = [a.strip() for a in _split_args(body_c[pm.end():close])]
                dyn_names = {n for f in reached for t, n in f.params
                             if re.match(r"^(string|bytes)(\s|$)|.*\[\s*\d*\s*\]", t)}
                if sum(a in dyn_names for a in args) >= 2:
                    add("BRIDGE-PACKED-COLLISION", "MEDIUM",
                        f"`abi.encodePacked` with two dynamic values in the signed hash of `{c.name}.{fn.name}`",
                        "`encodePacked(\"ab\",\"c\") == encodePacked(\"a\",\"bc\")`, so one signature covers "
                        "several payloads. Use `abi.encode` or EIP-712.")
                    break
    return sites, out, structs, consts


def abi_index(sol: list[_SolSrc]) -> dict[str, set[int | None]]:
    """External/public function name -> argument counts (None: any, for public getters)."""
    out: dict[str, set[int | None]] = {}
    for ss in sol:
        clean_lines = ss.clean.split("\n")
        for c in ss.contracts:
            if c.kind == "library":
                continue
            for fn in c.functions:
                if fn.kind == "function" and fn.visibility in ("public", "external"):
                    out.setdefault(fn.name, set()).add(len([p for p in fn.params if p[0]]))
            for name, meta in c.state_vars.items():
                line_text = clean_lines[meta["line"] - 1] if meta["line"] else ""
                if re.search(r"\bpublic\b", line_text):
                    out.setdefault(name, set()).add(None)
    return out


# --------------------------------------------------------------------------- #
# The bridge
# --------------------------------------------------------------------------- #


STATUS_RANK = ("bound", "unlinked", "unbound", "drift", "replayable", "oracle")


def _worse(cur: str, new: str) -> str:
    return new if STATUS_RANK.index(new) > STATUS_RANK.index(cur) else cur


def _link(sign: SignSite, verifies: list[VerifySite], backend_text: str) -> VerifySite | None:
    if sign.kind == "typed" and sign.struct:
        cands = [v for v in verifies if v.typehash and v.typehash.name == sign.struct.name]
        if not cands:
            return None
        named = [v for v in cands if re.search(rf"\b{re.escape(v.function)}\b", backend_text)]
        return (named or cands)[0]
    if sign.kind == "raw":
        raw = [v for v in verifies if v.method == "raw"]
        named = [v for v in raw if re.search(rf"\b{re.escape(v.function)}\b", backend_text)]
        if named:
            return named[0]
        return raw[0] if len(raw) == 1 else None
    return None


def analyze(sources: list[tuple[str, str]]) -> BridgeReport:
    """Run the bridge validator over ``(relative path, text)`` pairs from one repository."""
    rep = BridgeReport()
    sol = [_sol_src(rel, raw) for rel, raw in sources if rel.lower().endswith(".sol")]
    backend = [_Src(rel, raw) for rel, raw in sources
               if not rel.lower().endswith(".sol") and scoring._lang(rel) in (scoring.PY, scoring.JS, scoring.HTML)
               and WEB3_HINT.search(raw)]

    contract_findings: list[Finding] = []
    for ss in sol:
        v, f, _, _ = scan_solidity(ss)
        rep.verifies += v
        contract_findings += f

    texts = {s.rel: s.keep for s in backend}
    for src in backend:
        sites, f = scan_backend(src)
        rep.signs += sites
        rep.findings += f

    # Pair each backend signing site with its verifier and judge the pair.
    for s in rep.signs:
        if s.kind == "send" or (s.client and not s.server_key and s.kind == "raw"):
            # sends are not signatures; a user signing with their own wallet leaves only the contract side to judge
            continue
        v = _link(s, rep.verifies, texts.get(s.file, ""))
        link = BridgeLink(s, v, "bound")
        rep.links.append(link)

        def add(rule, sev, title, mitigation, file=s.file, line=s.line):
            src_lines = next((b.lines for b in backend if b.rel == file), [])
            rep.findings.append(Finding(rule, sev, LAYER, title, file, line, scoring.snippet(src_lines, line), mitigation))

        if s.server_key and s.handler and s.has_input and not s.has_auth:
            link.status = _worse(link.status, "oracle")
        if v is None:
            link.status = _worse(link.status, "unlinked")
            if s.kind == "raw" or (s.kind == "typed" and s.domain):
                missing = [x for x, ok in (("chain id", s.has_chain), ("contract address", s.has_contract)) if not ok]
                if missing and s.server_key:
                    add("BRIDGE-SIG-UNBOUND", "HIGH",
                        "Server signature not bound to the " + " and ".join(missing),
                        "Sign EIP-712 typed data with `chainId` and `verifyingContract` in the domain, or put "
                        "`block.chainid` and the contract address into the signed hash.")
                    link.status = _worse(link.status, "unbound")
            if s.server_key and not s.has_nonce:
                add("BRIDGE-SIG-NO-NONCE", "HIGH", "Server signature carries no nonce",
                    "Add a nonce (or unique id) to the payload and make the contract mark it used; otherwise the "
                    "same signature can be submitted again.")
                link.status = _worse(link.status, "replayable")
            if s.kind == "typed" and s.struct and rep.verifies and s.server_key:
                link.notes.append(f"no contract in this repository hashes `{s.struct.name}`")
            continue

        # Linked: compare both sides.
        if s.kind == "typed" and s.struct and v.typehash:
            if s.struct.normalized() != v.typehash.normalized():
                add("BRIDGE-TYPEHASH-DRIFT", "HIGH",
                    f"Backend signs `{s.struct.signature}` but `{v.contract}.{v.function}` hashes "
                    f"`{v.typehash.signature}`",
                    "Generate the backend types from the contract (or the other way round) so field names, "
                    "types and order match exactly. A drifted struct either fails every signature or binds "
                    "a value to the wrong field.")
                link.status = _worse(link.status, "drift")
                link.notes.append("struct fields differ")
        if s.kind == "typed" and s.domain:
            for key, want in (("name", v.domain_name), ("version", v.domain_version)):
                got = s.domain.literal(key)
                if want is not None and got is not None and got != want:
                    add("BRIDGE-DOMAIN-DRIFT", "MEDIUM",
                        f"EIP-712 domain {key} `{got}` (backend) != `{want}` ({v.contract})",
                        "Read the domain from the contract (`eip712Domain()`, EIP-5267) at startup instead of "
                        "hard-coding it; a mismatch means signatures for an old deployment are still being minted.",
                        line=s.domain.line)
                    link.status = _worse(link.status, "drift")
                    link.notes.append(f"domain {key} differs")
            if v.domain_fields is None and v.method == "eip712":
                missing = [x for x in ("chainId", "verifyingContract") if x not in s.domain.fields]
                if missing:
                    add("BRIDGE-DOMAIN-DRIFT", "MEDIUM",
                        f"Backend domain lacks {', '.join(missing)} that `{v.contract}` hashes into its separator",
                        "Include every EIP712Domain field the contract uses; read them from `eip712Domain()`.",
                        line=s.domain.line)
                    link.status = _worse(link.status, "drift")
                    link.notes.append("domain fields differ")
        if not v.replay_guard:
            title = (f"`{v.contract}.{v.function}` never consumes the nonce the backend signs" if s.has_nonce
                     else f"`{v.contract}.{v.function}` accepts the same signature again")
            add("BRIDGE-SIG-REPLAY", "HIGH", title,
                "Mark the nonce (or the digest) used before any effect: `if (used[nonce]) revert(); used[nonce] = "
                "true;` or OpenZeppelin `Nonces._useCheckedNonce`.", file=v.file, line=v.line)
            link.status = _worse(link.status, "replayable")
        if not v.deadline:
            if s.has_expiry:
                add("BRIDGE-DEADLINE-UNENFORCED", "HIGH",
                    f"Backend signs an expiry but `{v.contract}.{v.function}` never checks it",
                    "Require `block.timestamp <= deadline` in the verifying function; the backend's expiry is "
                    "only a promise until the contract enforces it.", file=v.file, line=v.line)
                link.status = _worse(link.status, "replayable")
            else:
                link.notes.append("signature never expires")
        if not (v.chain_bound and v.contract_bound):
            link.status = _worse(link.status, "unbound")

    # Contract-side findings, with duplicates of link findings removed.
    reported = {(f.rule, f.file, f.line) for f in rep.findings}
    for f in contract_findings:
        if (f.rule, f.file, f.line) not in reported:
            rep.findings.append(f)
    for v in rep.verifies:
        if any(l.verify is v for l in rep.links):
            continue
        if not v.replay_guard:
            rep.findings.append(Finding(
                "BRIDGE-SIG-REPLAY", "HIGH", LAYER, f"`{v.contract}.{v.function}` accepts the same signature again",
                v.file, v.line, _sol_line(sol, v), "Mark the nonce (or the digest) used before any effect, or use "
                "OpenZeppelin `Nonces._useCheckedNonce`.", contract=v.contract))
        if not v.deadline:
            rep.findings.append(Finding(
                "BRIDGE-SIG-NO-EXPIRY", "LOW", LAYER, f"Signatures accepted by `{v.contract}.{v.function}` never expire",
                v.file, v.line, _sol_line(sol, v), "Add a `deadline` field to the signed payload and require "
                "`block.timestamp <= deadline`.", contract=v.contract))

    # Backend calls against the ABI the repository's contracts expose.
    abi = abi_index(sol)
    if abi:
        names = sorted(abi)
        for src in backend:
            for name, n, overrides, line in backend_calls(src):
                rep.calls += 1
                if name in abi:
                    arities = abi[name]
                    if n is None or None in arities or n in arities or (overrides and n - 1 in arities):
                        continue
                    want = ", ".join(str(a) for a in sorted(a for a in arities if a is not None))
                    rep.findings.append(Finding(
                        "BRIDGE-ABI-DRIFT", "MEDIUM", LAYER,
                        f"Backend calls `{name}` with {n} argument(s); the contract takes {want}",
                        src.rel, line, src.snip(line),
                        "Regenerate the ABI/bindings from the current build (typechain, wagmi cli, abigen) instead of "
                        "hand-written ABIs."))
                elif name not in STANDARD_NAMES:
                    close = difflib.get_close_matches(name, names, n=1, cutoff=0.75)
                    if close:
                        rep.findings.append(Finding(
                            "BRIDGE-ABI-DRIFT", "MEDIUM", LAYER,
                            f"Backend calls `{name}`, which no contract here exposes (closest: `{close[0]}`)",
                            src.rel, line, src.snip(line),
                            "Regenerate the ABI/bindings from the current build; a renamed function means this "
                            "code path fails at runtime or targets an old deployment."))

    # One finding per (rule, file, line).
    seen: set[tuple[str, str, int]] = set()
    uniq = []
    for f in rep.findings:
        key = (f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    rep.findings = uniq
    return rep


def _sol_line(sol: list[_SolSrc], v: VerifySite) -> str:
    for ss in sol:
        if ss.rel == v.file:
            return scoring.snippet(ss.raw.splitlines(), v.line)
    return ""


def relevant(rel: str, raw: str) -> bool:
    """Whether a file is worth keeping in memory for the bridge pass."""
    if rel.lower().endswith(".sol"):
        return True
    return bool(WEB3_HINT.search(raw))


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def _yn(v: bool) -> str:
    return "yes" if v else "no"


def html_section(bridge: dict, esc) -> list[str]:
    """Bridge map for the HTML report. ``bridge`` is ``BridgeReport.as_dict()``; ``esc`` escapes HTML."""
    links, orphans = bridge.get("links", []), bridge.get("unlinked_verifiers", [])
    if not links and not orphans:
        return []
    out = ["<h2>Bridge map</h2>",
           '<p class="muted">Each place the backend signs with a server key, paired with the contract function '
           "that verifies it. Chain, contract, nonce and expiry are judged on the pair.</p>"]
    if links:
        out.append('<div class="scroll"><table><tr><th>Backend</th><th>Route</th><th>Signs</th><th>Verifier</th>'
                   "<th>Auth</th><th>Chain</th><th>Contract</th><th>Nonce used</th><th>Expiry checked</th>"
                   "<th>Status</th></tr>")
        for l in links:
            s, v = l["sign"], l["verify"]
            ver = (f"{esc(v['contract'])}.{esc(v['function'])}<br><span class=\"muted\">{esc(v['file'])}:{v['line']}</span>"
                   if v else '<span class="muted">not found</span>')
            # once linked, the contract decides what the digest is bound to
            chain = v["chain_bound"] if v else s["chain_id"]
            contract = v["contract_bound"] if v else s["contract"]
            nonce = v["replay_guard"] if v else s["nonce"]
            expiry = v["deadline"] if v else s["expiry"]
            route = esc(s["route"]) if s["route"] else '<span class="muted">-</span>'
            auth = _yn(s["auth"]) if s["route"] else "-"
            note = "<br><span class=\"muted\">" + esc("; ".join(l["notes"])) + "</span>" if l["notes"] else ""
            out.append(f"<tr><td class=\"loc\">{esc(s['file'])}:{s['line']}</td><td>{route}</td>"
                       f"<td><code>{esc(s['struct'] or s['kind'] + ' message')}</code></td><td>{ver}</td>"
                       f"<td>{auth}</td><td>{_yn(bool(chain))}</td><td>{_yn(bool(contract))}</td>"
                       f"<td>{_yn(bool(nonce))}</td><td>{_yn(bool(expiry))}</td>"
                       f"<td><b>{esc(l['status'])}</b>{note}</td></tr>")
        out.append("</table></div>")
    if orphans:
        out.append("<p>Verifiers with no signer in this repository: " + ", ".join(
            f"<code>{esc(v['contract'])}.{esc(v['function'])}</code> ({esc(v['file'])}:{v['line']}, "
            f"{'nonce used' if v['replay_guard'] else 'no nonce'}, {'deadline' if v['deadline'] else 'no deadline'})"
            for v in orphans) + ".</p>")
    if bridge.get("contract_calls_checked"):
        out.append(f'<p class="muted">{bridge["contract_calls_checked"]} backend contract call(s) checked against the '
                   "ABI of the contracts in this repository.</p>")
    return out


def text_lines(bridge: dict) -> list[str]:
    out = []
    for l in bridge.get("links", []):
        s, v = l["sign"], l["verify"]
        target = f"{v['contract']}.{v['function']} ({v['file']}:{v['line']})" if v else "no verifier found"
        out.append(f"  {l['status']:<10} {s['file']}:{s['line']} {s['struct'] or s['kind'] + ' message'} -> {target}")
    for v in bridge.get("unlinked_verifiers", []):
        out.append(f"  {'verifier':<10} {v['contract']}.{v['function']} ({v['file']}:{v['line']}) has no signer here")
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def add_bridge_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("target", help="repository or directory holding the contracts and the backend")
    ap.add_argument("--json", action="store_true", help="print the bridge map and findings as JSON")
    ap.add_argument("--fail-on", default="HIGH", choices=list(scoring.SEVERITIES) + ["NONE"],
                    help="exit 1 when a bridge finding is at least this severe (default: HIGH)")


def cmd_bridge(args) -> int:
    target = Path(args.target).expanduser()
    try:
        result, _ = scoring.score_path(target, frozenset())
    except (FileNotFoundError, OSError) as exc:
        print(f"foundryguard: {exc}", file=sys.stderr)
        return 2
    findings = [f for f in result.findings if f.layer == LAYER]
    bridge = result.bridge or {}
    if args.json:
        print(json.dumps({"bridge": bridge, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(f"bridge: {len(bridge.get('links', []))} signing site(s), "
              f"{len(bridge.get('unlinked_verifiers', [])) + sum(1 for l in bridge.get('links', []) if l['verify'])} "
              f"verifier(s), {len(findings)} finding(s)")
        for ln in text_lines(bridge):
            print(ln)
        for f in findings:
            print(f"  {f.severity:<8} {(f.signature or '-'):<6} {f.rule:<30} {f.location}  {f.title}")
    if args.fail_on == "NONE":
        return 0
    worst = scoring.SEVERITIES.index(args.fail_on)
    return 1 if any(scoring.SEVERITIES.index(f.severity) <= worst for f in findings) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="foundryguard-bridge",
                                 description="Check where the backend meets the contracts (Layer 12).")
    add_bridge_args(ap)
    return cmd_bridge(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
