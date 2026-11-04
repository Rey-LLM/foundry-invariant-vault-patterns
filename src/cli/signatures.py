"""Layer 13: the FoundryGuard signature database.

103 named signatures, each a separate failure mode with a CWE or SWC reference, a fixed severity, a one-line
mitigation and a short fix example that the HTML report prints next to the hit.

* FG-01..FG-50: the contract side (Solidity): reentrancy, price and balance manipulation, oracles, transient
  storage, access control, proxies and diamonds, signatures, ordering, governance, arithmetic.
* FG-51..FG-103: the web side: backend code, the HTTP surface of a page, dependency manifests, and the
  backend-to-contract bridge (Layer 12).

The detectors live where the text is parsed: Solidity rules in ``scoring.check_solidity``, line rules in
``scoring.LINE_RULES``, response-header rules in ``scoring.check_headers``, the bridge rules in
``web_surface.py``, and the file-level backend checks plus the dependency check below. This module never
imports ``scoring``.

``foundryguard.toml`` can move a signature to another severity or switch it off::

    [score.severity]
    "FG-02" = "MEDIUM"           # by signature id
    "WEB-RATE-LIMIT" = "off"     # or by rule name; any rule FoundryGuard emits can be tuned this way
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

LAYER_ID = "L13"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
OFF = "off"
WEB3_LAST = 50  # FG-01..FG-50 contract side, FG-51..FG-103 web side


@dataclass(frozen=True)
class Signature:
    id: str
    rule: str  # the rule name findings carry
    stack: str  # solidity | backend | http | deps | bridge
    severity: str
    ref: str  # CWE / SWC reference
    title: str
    mitigation: str
    fix: str  # short before/after or replacement snippet
    aliases: tuple[str, ...] = ()  # other rule names that are the same flaw
    fixed: bool = True  # False: the detector picks the severity per hit, the catalog value is the worst case

    @property
    def surface(self) -> str:
        return "web3" if int(self.id[3:]) <= WEB3_LAST else "web2"

    def as_dict(self) -> dict:
        d = asdict(self)
        d["surface"] = self.surface
        return d


def _sig(n: int, rule: str, stack: str, sev: str, ref: str, title: str, mitigation: str, fix: str,
         aliases: tuple[str, ...] = (), fixed: bool = True) -> Signature:
    return Signature(f"FG-{n:02d}", rule, stack, sev, ref, title, mitigation, fix, aliases, fixed)


SOL, BACK, HTTP, DEPS, BRIDGE = "solidity", "backend", "http", "deps", "bridge"

SIGNATURES: tuple[Signature, ...] = (
    # ------------------------------------------------------------------ contract side: FG-01..FG-50
    _sig(1, "SOL-ZERO-ADDRESS", SOL, "HIGH", "CWE-20 / SWC-123",
         "Address parameter stored without a zero-address check",
         "Revert on `address(0)` before storing a role, a token, a treasury or an oracle.",
         "if (newOwner == address(0)) revert ZeroAddress();\nowner = newOwner;"),
    _sig(2, "SOL-DIV-BEFORE-MUL", SOL, "HIGH", "CWE-682 / SWC-101",
         "Division before multiplication loses precision",
         "Multiply first, or use `Math.mulDiv(a, b, c)` so the intermediate keeps full precision.",
         "// was: amount / total * rate\nuint256 out = Math.mulDiv(amount, rate, total);"),
    _sig(3, "SOL-TX-ORIGIN", SOL, "CRITICAL", "CWE-477 / SWC-115",
         "Authorization through tx.origin",
         "Authorize `msg.sender`; any contract the user calls can act as them under `tx.origin`.",
         "require(msg.sender == owner, \"not owner\");"),
    _sig(4, "SOL-WEAK-RANDOMNESS", SOL, "HIGH", "CWE-330 / SWC-120",
         "Randomness derived from block values",
         "Use Chainlink VRF or commit-reveal; timestamp, prevrandao and blockhash are known to the block builder.",
         "uint256 requestId = vrfCoordinator.requestRandomWords(req);\n// use the word in fulfillRandomWords"),
    _sig(5, "SOL-UNCHECKED-CALL", SOL, "HIGH", "CWE-252 / SWC-104",
         "Low-level call or send whose result is ignored",
         "Capture the bool and revert on failure, or use `Address.sendValue` / `functionCall`.",
         "(bool ok, ) = to.call{value: amount}(\"\");\nif (!ok) revert TransferFailed();"),
    _sig(6, "SOL-ERC20-UNCHECKED", SOL, "HIGH", "CWE-252 / SWC-104",
         "ERC-20 transfer/transferFrom/approve whose bool is ignored",
         "Use OpenZeppelin `SafeERC20` (`safeTransfer`, `safeTransferFrom`, `forceApprove`); USDT-style tokens "
         "return false or nothing instead of reverting.",
         "using SafeERC20 for IERC20;\ntoken.safeTransfer(to, amount);"),
    _sig(7, "SOL-ARBITRARY-FROM", SOL, "CRITICAL", "CWE-285",
         "transferFrom pulls from a caller-chosen address",
         "Pull only from `msg.sender` (or from an address that signed a permit for this exact call); anyone "
         "can otherwise drain every wallet that approved the contract.",
         "token.safeTransferFrom(msg.sender, address(this), amount);"),
    _sig(8, "SOL-UNBOUNDED-LOOP", SOL, "HIGH", "CWE-834 / SWC-128",
         "Loop over a storage array that anyone can grow",
         "Bound the loop (paginate with start/count), or keep a running total instead of iterating; a long "
         "array pushes the call past the block gas limit and locks the function.",
         "function process(uint256 start, uint256 count) external {\n    uint256 end = Math.min(start + count, items.length);\n    for (uint256 i = start; i < end; ++i) { ... }\n}"),
    _sig(9, "SOL-CEI-DRIFT", SOL, "HIGH", "CWE-841 / SWC-107",
         "Reentrancy: state written after an external call",
         "Follow checks-effects-interactions: update balances and totals before the call, or add `nonReentrant`.",
         "balances[msg.sender] = 0;            // effect first\n(bool ok, ) = msg.sender.call{value: amt}(\"\");\nif (!ok) revert TransferFailed();"),
    _sig(10, "SOL-READONLY-REENTRANCY", SOL, "HIGH", "CWE-841 / SWC-107",
         "View function exposes state that is stale during an external call",
         "Finish every state write before the external call, or make the view revert while the reentrancy lock "
         "is held (`if (_reentrancyGuardEntered()) revert Reentrancy();`). Integrators that price off this view "
         "can be fed the half-updated value.",
         "function getRate() external view returns (uint256) {\n    if (_reentrancyGuardEntered()) revert Reentrancy();\n    return totalAssets * 1e18 / totalShares;\n}"),
    _sig(11, "SOL-SPOT-PRICE", SOL, "HIGH", "CWE-807",
         "Price read from a pool's spot reserves (flash-loan manipulable)",
         "Use a TWAP over a long enough window or a Chainlink feed with bounds; spot reserves move inside a flash loan.",
         "uint256 price = oracle.consult(token, 1800); // 30-minute TWAP, not getReserves()"),
    _sig(12, "SOL-DONATION-DRIFT", SOL, "MEDIUM", "CWE-682",
         "Accounting reads the contract's own balance (donation manipulable)",
         "Track deposits in an internal variable; anyone can move `balanceOf(this)` with a direct transfer.",
         "totalAssets += amount;   // internal ledger\n// not: token.balanceOf(address(this))"),
    _sig(13, "SOL-SHARE-INFLATION", SOL, "HIGH", "CWE-1339",
         "First-depositor share inflation (no virtual offset)",
         "Add virtual shares/assets (`_decimalsOffset`) or mint dead shares on the first deposit.",
         "function _decimalsOffset() internal pure override returns (uint8) { return 6; }"),
    _sig(14, "SOL-FLASH-VOTE", SOL, "HIGH", "CWE-807",
         "Votes weighed by live balance (flash-loan votes)",
         "Weigh votes by a past checkpoint (`getPastVotes(account, proposalSnapshot)`), never the current balance.",
         "uint256 weight = token.getPastVotes(msg.sender, proposal.snapshot);"),
    _sig(15, "SOL-TWAP-SHORT-WINDOW", SOL, "HIGH", "CWE-807",
         "TWAP window shorter than 30 minutes (TWAP squeeze)",
         "A short window can be pushed over a few blocks for little cost. Use 30 minutes or more on liquid pools, "
         "longer on thin ones, and cross-check with a second source.",
         "uint32 constant TWAP_PERIOD = 30 minutes;"),
    _sig(16, "SOL-STALE-ORACLE", SOL, "MEDIUM", "CWE-672",
         "Oracle answer used without a staleness check",
         "Check `updatedAt` against the feed heartbeat before using the price; `latestAnswer()` has no timestamp.",
         "(, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();\nif (block.timestamp - updatedAt > HEARTBEAT) revert StalePrice();"),
    _sig(17, "SOL-ORACLE-BAD-PRICE", SOL, "MEDIUM", "CWE-20",
         "Oracle answer cast to uint without checking it is positive",
         "Revert when `answer <= 0`; a negative int256 cast to uint256 becomes a huge price.",
         "if (answer <= 0) revert BadPrice();\nuint256 price = uint256(answer);"),
    _sig(18, "SOL-TRANSIENT-LEAK", SOL, "HIGH", "CWE-459",
         "Transient storage slot set and never cleared",
         "Write the slot back to zero before the call returns; EIP-1153 clears it only at the end of the "
         "transaction, so the next call in a multicall or callback sees the stale value.",
         "assembly { tstore(SLOT, 1) }\n// ... work ...\nassembly { tstore(SLOT, 0) }"),
    _sig(19, "SOL-UNPROTECTED-MUTATION", SOL, "CRITICAL", "CWE-284 / SWC-105",
         "Privileged state writable by anyone",
         "Gate the function with `onlyOwner`/`onlyRole` (or an explicit `msg.sender` check) and emit an event.",
         "function setOracle(address o) external onlyOwner { oracle = o; emit OracleSet(o); }"),
    _sig(20, "SOL-UNGUARDED-INITIALIZER", SOL, "CRITICAL", "CWE-665",
         "Initializer without an initializer lock (can be called again)",
         "Use OpenZeppelin `initializer` (or a one-shot `initialized` flag) so the function runs once.",
         "function initialize(address owner_) external initializer { __Ownable_init(owner_); }"),
    _sig(21, "SOL-IMPL-NOT-DISABLED", SOL, "HIGH", "CWE-665",
         "Upgradeable implementation left uninitialized",
         "Call `_disableInitializers()` in the implementation's constructor; otherwise anyone can initialize the "
         "implementation itself, take ownership and (for UUPS) upgrade or self-destruct it.",
         "/// @custom:oz-upgrades-unsafe-allow constructor\nconstructor() { _disableInitializers(); }"),
    _sig(22, "SOL-UUPS-NO-AUTH", SOL, "CRITICAL", "CWE-284",
         "UUPS `_authorizeUpgrade` with no access check",
         "Restrict it (`onlyOwner` / `onlyRole(UPGRADER_ROLE)`); an empty body lets anyone upgrade the proxy.",
         "function _authorizeUpgrade(address) internal override onlyOwner {}"),
    _sig(23, "SOL-PROXY-STORAGE-COLLISION", SOL, "CRITICAL", "SWC-124 / CWE-123",
         "Proxy declares its own storage variables (slot collision)",
         "A delegating proxy shares storage with the implementation. Keep proxy state in EIP-1967 slots "
         "(`StorageSlot`), never in ordinary state variables at slot 0, 1, ...",
         "bytes32 internal constant IMPL_SLOT = bytes32(uint256(keccak256(\"eip1967.proxy.implementation\")) - 1);"),
    _sig(24, "SOL-DIAMOND-SLOT-REUSE", SOL, "CRITICAL", "SWC-124 / CWE-694",
         "Two diamond storage structs hashed to the same slot",
         "Give every facet's storage a unique namespace string (or use ERC-7201 `erc7201:<ns>`); a shared "
         "position makes two structs overwrite each other.",
         "bytes32 constant POSITION = keccak256(\"myproject.facet.staking.v1\");"),
    _sig(25, "SOL-STORAGE-GAP", SOL, "MEDIUM", "SWC-124",
         "Upgradeable base contract with state but no storage gap",
         "Reserve `uint256[50] private __gap;` (or use ERC-7201 namespaced storage); adding a variable later "
         "shifts every child contract's slots.",
         "uint256[49] private __gap;"),
    _sig(26, "SOL-DELEGATECALL", SOL, "CRITICAL", "SWC-112 / CWE-829",
         "delegatecall into a variable or caller-supplied target",
         "Only delegatecall into an immutable, audited implementation; never into an address the caller passes.",
         "address private immutable IMPL;\n(bool ok, ) = IMPL.delegatecall(data);",
         fixed=False),
    _sig(27, "SOL-ARBITRARY-CALL", SOL, "CRITICAL", "CWE-749",
         "Caller chooses both the target and the calldata of an external call",
         "Whitelist targets and selectors, or never hold approvals/funds in a contract that forwards arbitrary "
         "calls; `target.call(data)` with `token.transferFrom(victim, ...)` drains every approval.",
         "if (!allowedTarget[target]) revert TargetNotAllowed();\nif (bytes4(data) == IERC20.transferFrom.selector) revert SelectorNotAllowed();"),
    _sig(28, "SOL-SELFDESTRUCT", SOL, "HIGH", "SWC-106 / CWE-284",
         "selfdestruct in deployed code",
         "Remove it; after Cancun it only moves ether, before that it could brick every user of the contract.",
         "// delete the selfdestruct path; use a pause + withdraw flow instead"),
    _sig(29, "SOL-SIG-MALLEABLE", SOL, "MEDIUM", "SWC-117 / CWE-347",
         "Raw ecrecover accepts malleable (high-s) signatures",
         "Use OpenZeppelin `ECDSA.recover`, which rejects `s` in the upper half order; with raw `ecrecover` "
         "a second valid signature exists for every signature, which defeats used-signature maps.",
         "address signer = ECDSA.recover(digest, signature);"),
    _sig(30, "BRIDGE-RAW-ECRECOVER", SOL, "MEDIUM", "SWC-122 / CWE-252",
         "ecrecover result not checked against address(0)",
         "`ecrecover` returns address(0) for an invalid signature; compare against a non-zero signer or use `ECDSA.recover`.",
         "address signer = ecrecover(digest, v, r, s);\nif (signer == address(0) || signer != expected) revert BadSignature();"),
    _sig(31, "BRIDGE-SIG-REPLAY", SOL, "HIGH", "SWC-121 / CWE-294",
         "Signature can be submitted again (no nonce consumed)",
         "Mark the nonce (or digest) used before any effect, or use OpenZeppelin `Nonces._useCheckedNonce`.",
         "if (used[digest]) revert Replayed();\nused[digest] = true;",
         aliases=("BRIDGE-SIG-NO-NONCE",)),
    _sig(32, "BRIDGE-SIG-NO-DOMAIN", SOL, "HIGH", "SWC-121 / CWE-294",
         "Signature not bound to chain id and contract (cross-chain replay)",
         "Hash with EIP-712 (`_hashTypedDataV4`): the domain carries `block.chainid` and `address(this)`.",
         "bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(CLAIM_TYPEHASH, to, amount, nonce, deadline)));",
         aliases=("BRIDGE-SIG-UNBOUND",)),
    _sig(33, "BRIDGE-PACKED-COLLISION", SOL, "MEDIUM", "SWC-133 / CWE-328",
         "abi.encodePacked with two dynamic values in a signed hash",
         "`encodePacked(\"ab\",\"c\") == encodePacked(\"a\",\"bc\")`; use `abi.encode` or EIP-712.",
         "bytes32 h = keccak256(abi.encode(name, symbol));"),
    _sig(34, "BRIDGE-SIG-NO-EXPIRY", SOL, "LOW", "CWE-613",
         "Accepted signatures never expire",
         "Sign a `deadline` and require `block.timestamp <= deadline` in the verifier.",
         "if (block.timestamp > deadline) revert Expired();"),
    _sig(35, "SOL-TIMESTAMP-EQUALITY", SOL, "MEDIUM", "SWC-116 / CWE-829",
         "Logic depends on block.timestamp hitting an exact value",
         "Block times are set by the builder and skip seconds; compare with `>=` / `<=` against a window.",
         "if (block.timestamp >= saleStart && block.timestamp < saleEnd) { ... }"),
    _sig(36, "SOL-GAS-STIPEND", SOL, "MEDIUM", "SWC-134 / CWE-400",
         "Ether sent with a fixed gas stipend (transfer/send/gas: N)",
         "`transfer`/`send` forward 2300 gas, which smart-contract wallets and future gas repricing break. Use "
         "`call{value:}` with a checked result and a reentrancy guard.",
         "(bool ok, ) = payable(to).call{value: amount}(\"\");\nif (!ok) revert TransferFailed();"),
    _sig(37, "SOL-SHORT-CALLDATA", SOL, "MEDIUM", "CWE-130",
         "Calldata decoded by hand without a length check (short address)",
         "Check `calldatasize()` / `msg.data.length` before reading fixed offsets, or decode with `abi.decode`; "
         "short calldata reads zeros (or shifted bytes) into the amount and address.",
         "if (msg.data.length < 4 + 64) revert ShortCalldata();\n(address to, uint256 amt) = abi.decode(msg.data[4:], (address, uint256));"),
    _sig(38, "SOL-DIRTY-ORDER", SOL, "HIGH", "CWE-841",
         "Order executed without checking it is still open",
         "Before filling, check the order hash against filled/cancelled state and the maker nonce, and mark the "
         "filled amount before moving tokens.",
         "bytes32 h = hashOrder(order);\nif (cancelled[h] || filled[h] + amount > order.amount) revert OrderClosed();\nfilled[h] += amount;"),
    _sig(39, "SOL-SLIPPAGE-ZERO", SOL, "HIGH", "CWE-20",
         "Swap with a minimum output of zero (sandwichable)",
         "Pass a caller-supplied `minAmountOut` (computed off-chain with a tolerance) instead of 0.",
         "router.swapExactTokensForTokens(amountIn, minAmountOut, path, to, deadline);"),
    _sig(40, "SOL-DEADLINE-NOW", SOL, "MEDIUM", "CWE-20",
         "Swap deadline set to block.timestamp (no deadline)",
         "`block.timestamp` is always current when the transaction runs, so a held transaction never expires. "
         "Take the deadline from the caller.",
         "router.swapExactTokensForTokens(amountIn, minOut, path, to, userDeadline);"),
    _sig(41, "SOL-VOTE-DOUBLE-COUNT", SOL, "HIGH", "CWE-837",
         "Vote tally increased without a has-voted check",
         "Record a receipt per (proposal, voter) and revert on the second vote.",
         "if (hasVoted[id][msg.sender]) revert AlreadyVoted();\nhasVoted[id][msg.sender] = true;"),
    _sig(42, "SOL-DELEGATE-INFLATION", SOL, "HIGH", "CWE-682",
         "Delegation adds voting weight without removing it from the old delegate",
         "Move votes: subtract from the previous delegate and add to the new one in one step "
         "(OpenZeppelin `Votes._delegate` / `_moveDelegateVotes`).",
         "_moveDelegateVotes(delegates[msg.sender], to, balanceOf(msg.sender));\ndelegates[msg.sender] = to;"),
    _sig(43, "SOL-ETH-PUSH-LOOP", SOL, "HIGH", "SWC-113 / CWE-703",
         "Ether pushed to many recipients in one loop",
         "One reverting recipient blocks everyone. Credit balances and let each recipient withdraw (pull payments).",
         "pending[recipient] += share;   // in the loop\n// recipients call withdraw() themselves"),
    _sig(44, "SOL-MSG-VALUE-LOOP", SOL, "HIGH", "CWE-837",
         "msg.value read inside a loop (or a payable multicall)",
         "`msg.value` stays the same for every iteration and every delegatecall; account for the ether once.",
         "uint256 remaining = msg.value;\nfor (...) { remaining -= cost; }\nif (remaining != 0) revert WrongValue();"),
    _sig(45, "SOL-INPUT-VALIDATION", SOL, "HIGH", "CWE-20",
         "External function takes input and never validates any of it",
         "Reject zero amounts, zero addresses, out-of-range values and empty arrays with custom errors first.",
         "if (amount == 0) revert ZeroAmount();\nif (to == address(0)) revert ZeroAddress();"),
    _sig(46, "SOL-DIV-BY-TOTAL", SOL, "MEDIUM", "CWE-369",
         "Division by a total that can be zero",
         "Branch on `total == 0` before dividing.",
         "if (totalSupply == 0) return assets;\nreturn assets * totalSupply / totalAssets;"),
    _sig(47, "SOL-UNSAFE-DOWNCAST", SOL, "MEDIUM", "CWE-681 / SWC-101",
         "Integer downcast without a bound check",
         "Explicit casts to a smaller uint silently truncate in 0.8; use OpenZeppelin `SafeCast`.",
         "uint128 amount128 = SafeCast.toUint128(amount);"),
    _sig(48, "SOL-NO-OVERFLOW-CHECKS", SOL, "HIGH", "SWC-101 / CWE-190",
         "Compiler before 0.8 and arithmetic without SafeMath",
         "Move to Solidity 0.8 (checked arithmetic by default) or use SafeMath on every operation.",
         "pragma solidity 0.8.24;"),
    _sig(49, "SOL-UNCHECKED-MATH", SOL, "LOW", "CWE-190",
         "Subtraction or multiplication inside unchecked",
         "Keep `unchecked` to loop counters and proven bounds; write the bound next to each operation.",
         "unchecked { ++i; }  // only the counter"),
    _sig(50, "SOL-UNFUNDED-REWARDS", SOL, "HIGH", "CWE-682",
         "Reward rate set without checking the tokens are there",
         "Require `rewardRate * duration <= rewardToken.balanceOf(address(this))`, or pull the tokens in the same call.",
         "if (rate * duration > rewardToken.balanceOf(address(this))) revert NotFunded();"),

    # ------------------------------------------------------------------ web side: FG-51..FG-103
    _sig(51, "WEB-SECRET", BACK, "CRITICAL", "CWE-798",
         "Private key, API key, salt or secret hardcoded in source",
         "Load it from the environment or a secret manager, rotate it now, and purge it from git history.",
         "PRIVATE_KEY = os.environ[\"SIGNER_KEY\"]  # never a literal",
         aliases=("BRIDGE-MNEMONIC-LITERAL", "BRIDGE-RPC-KEY")),
    _sig(52, "WEB-WEAK-RANDOM", BACK, "HIGH", "CWE-338",
         "Math.random / random module used for tokens, nonces or secrets",
         "Use `crypto.randomUUID()` / `crypto.getRandomValues` in JS, `secrets` in Python, `random_bytes` in PHP.",
         "const token = crypto.randomBytes(32).toString(\"hex\");",
         aliases=("BRIDGE-WEAK-NONCE",)),
    _sig(53, "WEB-BODY-LIMIT", BACK, "HIGH", "CWE-770",
         "Request body size not capped",
         "Set an explicit cap: `app.config[\"MAX_CONTENT_LENGTH\"]` in Flask, `limits: { fileSize }` in multer, "
         "a reverse-proxy `client_max_body_size` elsewhere.",
         "app.config[\"MAX_CONTENT_LENGTH\"] = 1 * 1024 * 1024  # 1 MB"),
    _sig(54, "WEB-RATE-LIMIT", BACK, "HIGH", "CWE-307",
         "Login, signup, reset or OTP route with no rate limiter in the project",
         "Rate-limit credential and token routes per IP and per account (express-rate-limit, flask-limiter, "
         "slowapi) and lock out after repeated failures.",
         "limiter = Limiter(get_remote_address, app=app)\n@app.post(\"/login\")\n@limiter.limit(\"5/minute\")"),
    _sig(55, "WEB-CORS-ANY", BACK, "HIGH", "CWE-942",
         "CORS allows any origin",
         "List the exact origins that may call the API; never combine `*` (or a reflected origin) with credentials.",
         "cors({ origin: [\"https://app.example.com\"], credentials: true })",
         aliases=("URL-CORS-ANY",)),
    _sig(56, "WEB-EVAL", BACK, "CRITICAL", "CWE-95",
         "eval / exec / new Function on runtime data",
         "Never evaluate strings; parse the data (`json.loads`, `JSON.parse`) and dispatch on known values.",
         "handler = HANDLERS.get(name)\nif handler is None: abort(400)"),
    _sig(57, "WEB-COMMAND", BACK, "CRITICAL", "CWE-78",
         "Shell command built and executed at runtime",
         "Run the program with an argument list and no shell (`subprocess.run([...])`, `execFile`), and "
         "validate every argument against an allowlist.",
         "subprocess.run([\"ping\", \"-c\", \"1\", host], check=True, timeout=5)"),
    _sig(58, "WEB-SQL", BACK, "CRITICAL", "CWE-89",
         "SQL built from strings",
         "Use parameterized queries (`cursor.execute(sql, params)`, `db.query(sql, [params])`) or the ORM.",
         "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"),
    _sig(59, "WEB-NOSQL", BACK, "HIGH", "CWE-943",
         "NoSQL query built from the raw request object (operator injection)",
         "Pick the fields you expect and cast them to strings/numbers; `{\"password\": {\"$ne\": null}}` in a body "
         "otherwise matches every user. Never pass `$where`.",
         "const user = await User.findOne({ email: String(req.body.email) });"),
    _sig(60, "WEB-SSTI", BACK, "CRITICAL", "CWE-1336",
         "Template rendered from a string that contains request data",
         "Render fixed template files and pass user values as context variables; never build the template text.",
         "return render_template(\"hello.html\", name=request.args.get(\"name\", \"\"))"),
    _sig(61, "WEB-XSS", BACK, "HIGH", "CWE-79",
         "Untrusted HTML written into the page",
         "Write text with `textContent` / framework escaping; sanitize with DOMPurify when HTML is required.",
         "el.textContent = comment;  // or el.innerHTML = DOMPurify.sanitize(html)"),
    _sig(62, "WEB-SSRF", BACK, "HIGH", "CWE-918",
         "Server fetches a URL taken from the request",
         "Allowlist hosts, resolve the name and reject private, loopback and link-local addresses (169.254.169.254), "
         "and disable redirects; better, map an id from the request to a URL you control.",
         "host = urlparse(url).hostname\nif host not in ALLOWED_HOSTS: abort(400)\nrequests.get(url, timeout=5, allow_redirects=False)"),
    _sig(63, "WEB-XXE", BACK, "HIGH", "CWE-611",
         "XML parser resolves external entities",
         "Use `defusedxml`, or turn entity resolution off (`resolve_entities=False, no_network=True`, no `noent`, "
         "no `LIBXML_NOENT`).",
         "from defusedxml.ElementTree import fromstring\ndoc = fromstring(body)"),
    _sig(64, "WEB-DESERIALIZE", BACK, "HIGH", "CWE-502",
         "Insecure deserialization of untrusted data",
         "Deserialize only data formats without code execution (JSON, `yaml.safe_load`).",
         "data = json.loads(body)  # not pickle.loads(body)"),
    _sig(65, "WEB-PATH-TRAVERSAL", BACK, "HIGH", "CWE-22",
         "File path taken from the request",
         "Resolve the path, check it stays inside the allowed directory, and reject `..`.",
         "return send_from_directory(UPLOADS, secure_filename(name))"),
    _sig(66, "WEB-OPEN-REDIRECT", BACK, "MEDIUM", "CWE-601",
         "Redirect target taken from the request",
         "Redirect only to relative paths or an allowlist of hosts.",
         "if urlparse(nxt).netloc: nxt = \"/\"\nreturn redirect(nxt)"),
    _sig(67, "WEB-INPUT-VALIDATION", BACK, "HIGH", "CWE-20",
         "Request input used with no validation layer in the file",
         "Validate every field against a schema (pydantic, zod, joi, express-validator): type, length, range.",
         "const body = Body.parse(req.body);  // zod schema"),
    _sig(68, "WEB-MASS-ASSIGNMENT", BACK, "HIGH", "CWE-915",
         "Whole request body written into a model (parameter contamination)",
         "Copy only the fields the caller may set; otherwise `{\"role\": \"admin\", \"balance\": 1e9}` rides along.",
         "const { name, email } = req.body;\nawait User.update({ name, email }, { where: { id: req.user.id } });"),
    _sig(69, "WEB-IDOR", BACK, "HIGH", "CWE-639",
         "Record loaded by an id from the URL with no ownership check (BOLA/IDOR)",
         "Scope the lookup to the authenticated user (`WHERE id = ? AND owner_id = ?`) or check ownership "
         "before returning or changing the record.",
         "order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()"),
    _sig(70, "WEB-JWT-NONE", BACK, "HIGH", "CWE-347",
         "JWT signature or expiry not verified",
         "Verify the signature with a fixed algorithm list and check `exp`.",
         "jwt.decode(token, KEY, algorithms=[\"HS256\"])"),
    _sig(71, "WEB-TIMING-COMPARE", BACK, "MEDIUM", "CWE-208",
         "Secret, token or signature compared with == (timing leak)",
         "Compare in constant time: `hmac.compare_digest`, `crypto.timingSafeEqual`, `hash_equals`.",
         "if not hmac.compare_digest(given, expected): abort(401)"),
    _sig(72, "WEB-TOKEN-ENTROPY", BACK, "MEDIUM", "CWE-331",
         "Token with too little entropy (short or time-based)",
         "Use at least 16 random bytes (128 bits) from a CSPRNG; `uuid1`, `uniqid` and `Date.now()` are guessable.",
         "token = secrets.token_urlsafe(32)"),
    _sig(73, "WEB-WEAK-HASH", BACK, "LOW", "CWE-328",
         "MD5 or SHA-1 in use",
         "Use bcrypt/argon2 for passwords and SHA-256 or better elsewhere.",
         "hash = argon2.PasswordHasher().hash(password)"),
    _sig(74, "WEB-TOKEN-STORAGE", BACK, "MEDIUM", "CWE-922",
         "Auth token kept in localStorage",
         "Keep session tokens in `HttpOnly; Secure; SameSite` cookies, out of reach of page scripts.",
         "res.cookie(\"sid\", sid, { httpOnly: true, secure: true, sameSite: \"lax\" });"),
    _sig(75, "WEB-COOKIE-INSECURE", BACK, "MEDIUM", "CWE-614 / CWE-1004",
         "Session cookie missing Secure or HttpOnly",
         "Set `Secure; HttpOnly; SameSite=Lax` on session cookies so scripts and plain http cannot read them.",
         "resp.set_cookie(\"sid\", sid, secure=True, httponly=True, samesite=\"Lax\")",
         aliases=("URL-COOKIE-FLAGS",)),
    _sig(76, "WEB-CSRF", BACK, "MEDIUM", "CWE-352",
         "POST form without an anti-CSRF token",
         "Add a per-session CSRF token to the form and check it server side; set cookies `SameSite=Lax` or stricter.",
         "<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">"),
    _sig(77, "WEB-TLS-OFF", BACK, "HIGH", "CWE-295",
         "TLS certificate checks disabled",
         "Keep verification on; pin or trust the right CA bundle instead.",
         "requests.get(url, verify=\"/etc/ssl/certs/internal-ca.pem\")"),
    _sig(78, "WEB-PLAIN-HTTP", BACK, "MEDIUM", "CWE-319",
         "Plain http:// endpoint or page",
         "Use https:// for every endpoint and asset and redirect http to https.",
         "API_URL = \"https://api.example.com\"",
         aliases=("URL-NO-TLS",)),
    _sig(79, "WEB-MIXED-CONTENT", HTTP, "MEDIUM", "CWE-319",
         "http:// resource loaded by an https page",
         "Load every resource over https.",
         "<script src=\"https://cdn.example.com/app.js\"></script>"),
    _sig(80, "WEB-NO-SRI", BACK, "LOW", "CWE-353",
         "Third-party script without an integrity hash",
         "Add `integrity=\"sha384-...\"` and `crossorigin`, or self-host the script.",
         "<script src=\"https://cdn.example.com/lib.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>"),
    _sig(81, "WEB-DEBUG", BACK, "MEDIUM", "CWE-489",
         "Debug mode enabled",
         "Read debug flags from the environment and default them to off.",
         "app.run(debug=os.environ.get(\"FLASK_DEBUG\") == \"1\")"),
    _sig(82, "WEB-GLOBAL-STATE", BACK, "MEDIUM", "CWE-362",
         "Request handler mutates module-level state (race)",
         "Keep request state local or in a store with explicit locking; globals drift between requests and workers.",
         "with db.transaction(): counter.increment()"),
    _sig(83, "WEB-NO-HEADERS-MW", BACK, "MEDIUM", "CWE-693",
         "App sets no security headers (no helmet / Talisman)",
         "Add `helmet()` in Express or `flask-talisman` in Flask so HSTS, CSP, nosniff and frame options go out "
         "on every response.",
         "app.use(helmet());"),
    _sig(84, "URL-NO-CSP", HTTP, "HIGH", "CWE-693",
         "No Content-Security-Policy header",
         "Send a CSP that limits script sources (`default-src 'self'`; no `unsafe-inline`).",
         "Content-Security-Policy: default-src 'self'; frame-ancestors 'self'"),
    _sig(85, "URL-WEAK-CSP", HTTP, "MEDIUM", "CWE-693",
         "CSP allows unsafe-inline or unsafe-eval",
         "Drop `unsafe-inline` and `unsafe-eval`; use nonces or hashes for inline scripts.",
         "Content-Security-Policy: script-src 'self' 'nonce-<random>'"),
    _sig(86, "URL-NO-HSTS", HTTP, "MEDIUM", "CWE-319",
         "No Strict-Transport-Security header",
         "Send HSTS so browsers never fall back to http.",
         "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    _sig(87, "URL-NO-NOSNIFF", HTTP, "LOW", "CWE-693",
         "No X-Content-Type-Options: nosniff",
         "Send `X-Content-Type-Options: nosniff`.",
         "X-Content-Type-Options: nosniff"),
    _sig(88, "URL-CLICKJACKING", HTTP, "MEDIUM", "CWE-1021",
         "Page can be framed by any site",
         "Send `frame-ancestors 'self'` in the CSP (or `X-Frame-Options: DENY`).",
         "Content-Security-Policy: frame-ancestors 'self'"),
    _sig(89, "URL-VERSION-LEAK", HTTP, "LOW", "CWE-200",
         "Server or X-Powered-By header discloses a version",
         "Remove the version from the header.",
         "app.disable(\"x-powered-by\");"),
    _sig(90, "WEB-VULN-DEPENDENCY", DEPS, "HIGH", "CWE-1395",
         "Dependency (direct or transitive) pinned to a version with a known advisory",
         "Upgrade to the fixed version and run `npm audit` / `pip-audit` in CI; FoundryGuard ships only a short "
         "offline list of well-known advisories.",
         "npm install lodash@^4.17.21   # then commit the lockfile"),
    _sig(91, "BRIDGE-SIGNING-ORACLE", BRIDGE, "CRITICAL", "CWE-306",
         "Public route signs with the server key for any caller",
         "Authenticate the caller before the key is touched and derive the recipient from that identity.",
         "@app.post(\"/claim\")\n@login_required\ndef claim(): sign_for(current_user.wallet)"),
    _sig(92, "BRIDGE-OPEN-RELAYER", BRIDGE, "CRITICAL", "CWE-306",
         "Public route sends transactions from the server key for any caller",
         "Authenticate and rate-limit the route, and cap gas per caller.",
         "router.post(\"/relay\", requireAuth, limiter, relay);"),
    _sig(93, "BRIDGE-SIGNED-INPUT-UNCHECKED", BRIDGE, "HIGH", "CWE-20",
         "Request values signed without bounds",
         "Validate every signed field against a schema and the caller's entitlement before signing.",
         "if amount > entitlement(current_user): abort(403)"),
    _sig(94, "BRIDGE-KEY-FROM-REQUEST", BRIDGE, "CRITICAL", "CWE-522",
         "Private key or mnemonic read from the request",
         "Never accept key material over HTTP; keep the key in a KMS/HSM or the server environment.",
         "signer = Account.from_key(os.environ[\"SIGNER_KEY\"])"),
    _sig(95, "BRIDGE-KEY-LOGGED", BRIDGE, "HIGH", "CWE-532",
         "Key material written to a log or response",
         "Log the signer address instead, and rotate the key if this ever ran in production.",
         "log.info(\"signer %s\", signer.address)"),
    _sig(96, "BRIDGE-KEY-CLIENT", BRIDGE, "CRITICAL", "CWE-312",
         "Signing key shipped to the browser",
         "Public env prefixes are inlined into the bundle; sign on the server and rotate the key.",
         "// browser: use the user's wallet (EIP-1193), never new Wallet(KEY)"),
    _sig(97, "BRIDGE-TX-NONCE-RACE", BRIDGE, "MEDIUM", "CWE-362",
         "Transaction nonce read and set by hand without a lock",
         "Use a nonce manager or one queue per key, or read the `pending` count under a lock.",
         "const nonce = await provider.getTransactionCount(addr, \"pending\"); // under a mutex"),
    _sig(98, "BRIDGE-RECEIPT-STATUS", BRIDGE, "HIGH", "CWE-252",
         "Transaction receipt used without checking status",
         "Check `receipt.status == 1` before crediting or releasing anything off-chain.",
         "if (receipt.status !== 1) throw new Error(\"reverted\");"),
    _sig(99, "BRIDGE-REORG", BRIDGE, "MEDIUM", "CWE-345",
         "Chain events acted on with no confirmation depth",
         "Wait for N confirmations or the `finalized` block tag before crediting deposits.",
         "await tx.wait(12);"),
    _sig(100, "BRIDGE-ABI-DRIFT", BRIDGE, "MEDIUM", "CWE-628",
         "Backend calls a contract function that does not match the ABI",
         "Regenerate the ABI/bindings from the current build (typechain, wagmi cli, abigen).",
         "npx wagmi generate"),
    _sig(101, "BRIDGE-TYPEHASH-DRIFT", BRIDGE, "HIGH", "CWE-347",
         "Backend EIP-712 struct differs from the contract typehash",
         "Generate the backend types from the contract so names, types and order match exactly.",
         "const types = { Claim: [{ name: \"to\", type: \"address\" }, { name: \"amount\", type: \"uint256\" }] };"),
    _sig(102, "BRIDGE-DOMAIN-DRIFT", BRIDGE, "MEDIUM", "CWE-347",
         "Backend EIP-712 domain differs from the contract",
         "Read the domain from the contract (`eip712Domain()`, EIP-5267) at startup.",
         "const domain = await contract.eip712Domain();"),
    _sig(103, "BRIDGE-DEADLINE-UNENFORCED", BRIDGE, "HIGH", "CWE-613",
         "Backend signs an expiry the contract never checks",
         "Require `block.timestamp <= deadline` in the verifying function.",
         "if (block.timestamp > deadline) revert Expired();"),
)

BY_ID = {s.id: s for s in SIGNATURES}
BY_RULE: dict[str, Signature] = {}
for _s in SIGNATURES:
    BY_RULE[_s.rule] = _s
    for _a in _s.aliases:
        BY_RULE[_a] = _s


def lookup(rule: str) -> Signature | None:
    return BY_RULE.get(rule)


def severity(rule: str, default: str = "MEDIUM") -> str:
    sig = BY_RULE.get(rule)
    return sig.severity if sig else default


def severity_overrides(cfg: dict) -> dict[str, str]:
    """``[score.severity]`` from foundryguard.toml, keyed by rule name. Signature ids expand to their rules."""
    raw = (cfg.get("score") or {}).get("severity") or {}
    out: dict[str, str] = {}
    for key, val in raw.items():
        val = str(val).strip()
        val = OFF if val.lower() == OFF else val.upper()
        if val != OFF and val not in SEVERITIES:
            raise ValueError(f"foundryguard.toml [score.severity] {key!r}: {val!r} is not one of "
                             f"{', '.join(SEVERITIES)} or off")
        sig = BY_ID.get(str(key).upper())
        if sig:
            for rule in (sig.rule, *sig.aliases):
                out[rule] = val
        else:
            out[str(key)] = val
    return out


def apply(findings: list, overrides: dict[str, str] | None = None) -> list:
    """Stamp signature ids, fixes and catalog severities on findings; apply config overrides; drop 'off' rules."""
    overrides = overrides or {}
    kept = []
    for f in findings:
        sig = BY_RULE.get(f.rule)
        if sig:
            f.signature = sig.id
            f.fix = sig.fix
            if f.rule == sig.rule and sig.fixed:
                f.severity = sig.severity
        want = overrides.get(f.rule)
        if want == OFF:
            continue
        if want:
            f.severity = want
        kept.append(f)
    return kept


def hits(findings: list) -> dict[str, int]:
    out = {s.id: 0 for s in SIGNATURES}
    for f in findings:
        sid = getattr(f, "signature", None)
        if sid in out:
            out[sid] += 1
    return out


# --------------------------------------------------------------------------- #
# File-level backend checks
# --------------------------------------------------------------------------- #

FLASK_APP = re.compile(r"\bFlask\s*\(")
FLASK_BODY_READ = re.compile(r"request\.(get_json|json|data|files|form|stream|get_data)\b")
FLASK_CAP = re.compile(r"MAX_CONTENT_LENGTH|max_content_length|MAX_FORM_MEMORY_SIZE")
MULTER_CALL = re.compile(r"\bmulter\s*\(")
BODY_PARSER_HUGE = re.compile(r"(json|urlencoded|raw|text)\s*\(\s*\{[^}]*limit\s*:\s*['\"]\s*(\d+)\s*(mb|gb)", re.I)

AUTH_PATH = r"[^'\"]*(log-?in|sign-?in|sign-?up|register|reset|forgot|otp|2fa|mfa|verify|password|passwd|token|auth)[^'\"]*"
AUTH_ROUTE = re.compile(
    r"(@\s*[\w.]+\.(route|get|post|put|patch|api_route)|\b(app|router|api|server|fastify|route|bp|blueprint)\s*\.\s*"
    r"(get|post|put|patch|all|route))\s*\(\s*['\"`]" + AUTH_PATH + r"['\"`]", re.I)
RATE_LIMITER = re.compile(r"rate[-_ ]?limit|ratelimit|express-rate-limit|express-slow-down|flask_limiter|slowapi|"
                          r"\bLimiter\b|\blimiter\b|throttl|RateLimiter|@nestjs/throttler|bottleneck|rate_limiter", re.I)

# FG-62 SSRF through a variable: url = request.args["url"] ... requests.get(url)
REQUEST_VALUE = r"(request\.(args|form|values|json|get_json\(\)|data|GET|POST|query_params)|req\.(body|query|params)|\$_(GET|POST|REQUEST))"
TAINT_ASSIGN = re.compile(r"^\s*(?:const|let|var|\$)?\s*([A-Za-z_]\w*)\s*=\s*[^\n]*" + REQUEST_VALUE, re.M)
TAINT_DESTRUCTURE = re.compile(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req\.(body|query|params)\b")
HTTP_CLIENT = re.compile(r"(requests\.(get|post|put|delete|head|patch|request)|httpx\.(get|post|put|delete|request|stream)|"
                         r"urllib\.request\.urlopen|\burlopen|aiohttp\.ClientSession\(\)\.get|session\.get|\bfetch|"
                         r"axios(\.(get|post|put|delete|request))?|\bgot(\.(get|post))?|https?\.get|https?\.request|"
                         r"needle(\.\w+)?|superagent\.\w+|curl_init)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]")
# FG-69 IDOR
ID_LOOKUP = re.compile(r"findById\s*\(\s*req\.params\.\w+|findByPk\s*\(\s*req\.params\.\w+|"
                       r"findOne\s*\(\s*\{\s*_?id\s*:\s*req\.params\.\w+\s*\}\s*\)|"
                       r"\.get_or_404\s*\(\s*\w*id\s*\)|\.query\.get\s*\(\s*\w*id\s*\)|"
                       r"objects\.get\s*\(\s*(pk|id)\s*=\s*\w*(id|pk)\s*\)|"
                       r"WHERE\s+id\s*=\s*['\"]?\s*\.\s*\$_GET", re.I)
OWNERSHIP = re.compile(r"owner|user_id|userId|current_user|req\.user|request\.user|g\.user|authorize|"
                       r"permission|policy|can\(|abort\(\s*403|status\(\s*403|Forbidden", re.I)
# FG-75 cookies
COOKIE_CALL = re.compile(r"(?<![\w.])(?:(?!self\.|jar\.|cookiejar\.|cookies\.)[A-Za-z_$][\w$]*\.)?(set_cookie|cookie|setcookie)\s*\(\s*['\"]")
COOKIE_OWNER = {"py": ("set_cookie",), "js": ("cookie",), "php": ("setcookie",)}
# FG-83 headers middleware
EXPRESS_APP = re.compile(r"\bexpress\s*\(\s*\)")
HEADERS_PRESENT = re.compile(r"helmet|Talisman|flask_talisman|Content-Security-Policy|Strict-Transport-Security|"
                             r"X-Frame-Options|SecurityMiddleware|secure_headers|@fastify/helmet|lusca", re.I)
# FG-63 lxml with entity resolution left at its default
LXML_PARSE = re.compile(r"\betree\.(parse|fromstring|XML|iterparse)\s*\(")


def limiter_present(raw: str) -> bool:
    return bool(RATE_LIMITER.search(raw))


def headers_present(raw: str) -> bool:
    return bool(HEADERS_PRESENT.search(raw))


def _line(raw: str, offset: int) -> int:
    return raw.count("\n", 0, offset) + 1


def _call_args(raw: str, open_paren: int, limit: int = 800) -> str:
    depth = 0
    for i in range(open_paren, min(len(raw), open_paren + limit)):
        if raw[i] == "(":
            depth += 1
        elif raw[i] == ")":
            depth -= 1
            if depth == 0:
                return raw[open_paren + 1:i]
    return raw[open_paren + 1:open_paren + limit]


def check_backend(raw: str, lang: str) -> list[tuple[str, int, str]]:
    """(rule, line, title) hits for the file-level backend signatures. ``lang`` is "py", "js", "php" or "html"."""
    out: list[tuple[str, int, str]] = []
    if lang == "py":
        app = FLASK_APP.search(raw)
        if app and FLASK_BODY_READ.search(raw) and not FLASK_CAP.search(raw):
            out.append(("WEB-BODY-LIMIT", _line(raw, app.start()),
                        "Flask app reads request bodies and never sets `MAX_CONTENT_LENGTH` (no cap by default)"))
    if lang == "js":
        for m in MULTER_CALL.finditer(raw):
            close = raw.find(")", m.end())
            args = raw[m.end(): close if close >= 0 else m.end() + 400]
            if "limits" not in args:
                out.append(("WEB-BODY-LIMIT", _line(raw, m.start()),
                            "multer upload with no `limits` (file size is unbounded by default)"))
        for m in BODY_PARSER_HUGE.finditer(raw):
            size = int(m.group(2)) * (1024 if m.group(3).lower() == "gb" else 1)
            if size >= 50:
                out.append(("WEB-BODY-LIMIT", _line(raw, m.start()),
                            f"Body parser accepts {m.group(2)}{m.group(3)} per request"))
    if lang in ("py", "js", "php") and not limiter_present(raw):
        for m in AUTH_ROUTE.finditer(raw):
            out.append(("WEB-RATE-LIMIT", _line(raw, m.start()),
                        "Credential or token route with no rate limiter"))
    if lang not in ("py", "js", "php"):
        return out

    # FG-62 SSRF: a request value flows into an HTTP client through a variable
    tainted = {m.group(1) for m in TAINT_ASSIGN.finditer(raw)}
    for m in TAINT_DESTRUCTURE.finditer(raw):
        tainted |= {p.split(":")[-1].strip() for p in m.group(1).split(",") if p.strip()}
    tainted.discard("")
    for m in HTTP_CLIENT.finditer(raw):
        var = m.group(m.lastindex)
        if var in tainted:
            out.append(("WEB-SSRF", _line(raw, m.start()),
                        f"Outbound request to `{var}`, which comes from the request"))

    # FG-69 IDOR / BOLA
    if not OWNERSHIP.search(raw):
        for m in ID_LOOKUP.finditer(raw):
            out.append(("WEB-IDOR", _line(raw, m.start()),
                        "Record fetched by a URL id and returned with no ownership check"))

    # FG-75 cookie flags
    for m in COOKIE_CALL.finditer(raw):
        if m.group(1) not in COOKIE_OWNER[lang] or (lang == "js" and not re.search(r"\b(res|response|reply|ctx)\.cookie\s*\($",
                                                                                   raw[m.start():m.end()].rstrip("'\" "))):
            continue
        if re.search(r"\b(def|function)\s+$", raw[max(0, m.start() - 12):m.start()]):
            continue
        open_paren = raw.index("(", m.start())
        args = _call_args(raw, open_paren)
        low = re.sub(r"\s+", "", args.lower())
        if m.group(1) == "setcookie":
            if "=>" in low:
                secure = bool(re.search(r"['\"]secure['\"]=>true", low))
                http_only = bool(re.search(r"['\"]httponly['\"]=>true", low))
            else:
                parts = low.split(",")
                secure = len(parts) >= 6 and parts[5] == "true"
                http_only = len(parts) >= 7 and parts[6] == "true"
        else:
            secure = bool(re.search(r"secure(=|:)true", low))
            http_only = bool(re.search(r"httponly(=|:)true", low))
        missing = [n for n, ok in (("Secure", secure), ("HttpOnly", http_only)) if not ok]
        if missing:
            out.append(("WEB-COOKIE-INSECURE", _line(raw, m.start()),
                        f"Cookie set without {' and '.join(missing)}"))

    # FG-63 lxml parse with default entity handling
    if lang == "py" and re.search(r"\bfrom\s+lxml\b|\bimport\s+lxml\b", raw) and "defusedxml" not in raw \
            and re.search(REQUEST_VALUE + r"|request\.(data|stream|get_data)|\bupload|\bbody\b", raw) \
            and not re.search(r"resolve_entities\s*=\s*False|HTMLParser|lxml\.html", raw):
        for m in LXML_PARSE.finditer(raw):
            out.append(("WEB-XXE", _line(raw, m.start()),
                        "lxml parse without `resolve_entities=False` (external entities resolve on lxml < 5)"))
            break
    return out


def missing_security_headers(raw: str, lang: str) -> list[tuple[str, int, str]]:
    """FG-83: an Express or Flask app with no header middleware. The caller drops it if any file sets headers."""
    m = (EXPRESS_APP.search(raw) if lang == "js" else FLASK_APP.search(raw) if lang == "py" else None)
    if not m:
        return []
    kind = "Express" if lang == "js" else "Flask"
    return [("WEB-NO-HEADERS-MW", _line(raw, m.start()),
             f"{kind} app without helmet/Talisman or any security header (HSTS, CSP, nosniff, frame options)")]


# --------------------------------------------------------------------------- #
# FG-90 dependency manifests (offline, short list of well-known advisories)
# --------------------------------------------------------------------------- #

MANIFESTS = ("package.json", "package-lock.json", "requirements.txt")

# name -> list of (first affected or None, first fixed, advisory)
ADVISORIES: dict[str, dict[str, list[tuple[str | None, str, str]]]] = {
    "npm": {
        "lodash": [(None, "4.17.21", "CVE-2021-23337 command injection in template()")],
        "minimist": [(None, "1.2.6", "CVE-2021-44906 prototype pollution")],
        "jsonwebtoken": [(None, "9.0.0", "CVE-2022-23529 / CVE-2022-23540 key handling")],
        "axios": [(None, "0.21.1", "CVE-2020-28168 SSRF through redirects")],
        "node-fetch": [(None, "2.6.7", "CVE-2022-0235 cookie/authorization header leak on redirect")],
        "express": [(None, "4.19.2", "CVE-2024-29041 open redirect")],
        "jquery": [(None, "3.5.0", "CVE-2020-11022 XSS in htmlPrefilter")],
        "handlebars": [(None, "4.7.7", "CVE-2021-23369 remote code execution with compile()")],
        "serialize-javascript": [(None, "3.1.0", "CVE-2020-7660 code injection")],
    },
    "pypi": {
        "pyyaml": [(None, "5.4", "CVE-2020-14343 code execution in full_load")],
        "requests": [(None, "2.32.0", "CVE-2024-35195 verify=False sticks to the session")],
        "jinja2": [(None, "2.11.3", "CVE-2020-28493 ReDoS in urlize")],
        "urllib3": [(None, "1.26.5", "CVE-2021-33503 ReDoS in URL parsing")],
        "flask": [(None, "2.2.5", "CVE-2023-30861 session cookie cached by proxies"),
                  ("2.3.0", "2.3.2", "CVE-2023-30861 session cookie cached by proxies")],
        "werkzeug": [(None, "2.2.3", "CVE-2023-25577 multipart parsing DoS")],
    },
}


def _ver(text: str) -> tuple[int, ...] | None:
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", text or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _advisory(eco: str, name: str, version: tuple[int, ...]) -> str | None:
    for lo, fixed, text in ADVISORIES[eco].get(name.lower(), []):
        if (lo is None or _cmp(version, _ver(lo)) >= 0) and _cmp(version, _ver(fixed)) < 0:
            return f"{text}; fixed in {fixed}"
    return None


def _range_ceiling(spec: str) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    """(lowest, exclusive upper bound) for exact, ^ and ~ npm ranges; None for anything wider."""
    spec = spec.strip()
    if re.fullmatch(r"=?v?\d+\.\d+\.\d+", spec):
        v = _ver(spec.lstrip("="))
        return v, v + (1,)
    m = re.fullmatch(r"([~^])(\d+)\.(\d+)\.(\d+)", spec)
    if not m:
        return None
    op, a, b, c = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
    if op == "~":
        return (a, b, c), (a, b + 1, 0)
    if a > 0:
        return (a, b, c), (a + 1, 0, 0)
    return (a, b, c), (0, b + 1, 0)


def _find_line(raw: str, *needles: str) -> int:
    for n in needles:
        i = raw.find(n)
        if i >= 0:
            return _line(raw, i)
    return 1


def check_manifest(name: str, raw: str) -> list[tuple[str, int, str]]:
    """FG-90 hits for package.json, package-lock.json and requirements.txt."""
    out: list[tuple[str, int, str]] = []
    base = name.rsplit("/", 1)[-1].lower()
    if base == "requirements.txt" or (base.startswith("requirements") and base.endswith(".txt")):
        for i, ln in enumerate(raw.splitlines(), 1):
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([0-9][\w.]*)", ln)
            if m:
                v = _ver(m.group(3))
                adv = v and _advisory("pypi", m.group(1), v)
                if adv:
                    out.append(("WEB-VULN-DEPENDENCY", i, f"`{m.group(1)}=={m.group(3)}`: {adv}"))
        return out
    try:
        data = json.loads(raw)
    except ValueError:
        return out
    if not isinstance(data, dict):
        return out
    if base == "package.json":
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for dep, spec in (data.get(section) or {}).items():
                if not isinstance(spec, str):
                    continue
                rng = _range_ceiling(spec)
                if not rng:
                    continue
                for lo, fixed, text in ADVISORIES["npm"].get(dep.lower(), []):
                    if _cmp(rng[1], _ver(fixed)) <= 0 and (lo is None or _cmp(rng[0], _ver(lo)) >= 0):
                        out.append(("WEB-VULN-DEPENDENCY", _find_line(raw, f'"{dep}"'),
                                    f"`{dep}@{spec}` cannot reach {fixed}: {text}"))
                        break
        return out
    if base == "package-lock.json":
        seen: set[tuple[str, str]] = set()
        for path, meta in (data.get("packages") or {}).items():
            if not path or not isinstance(meta, dict):
                continue
            dep = path.rsplit("node_modules/", 1)[-1]
            ver = meta.get("version", "")
            v = _ver(ver)
            adv = v and _advisory("npm", dep, v)
            if adv and (dep, ver) not in seen:
                seen.add((dep, ver))
                kind = "transitive" if path.count("node_modules/") > 1 or meta.get("dev") is not None else "locked"
                out.append(("WEB-VULN-DEPENDENCY", _find_line(raw, f'"{path}"'),
                            f"{kind} `{dep}@{ver}`: {adv}"))

        def walk(deps: dict, depth: int) -> None:
            for dep, meta in (deps or {}).items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version", "")
                v = _ver(ver)
                adv = v and _advisory("npm", dep, v)
                if adv and (dep, ver) not in seen:
                    seen.add((dep, ver))
                    out.append(("WEB-VULN-DEPENDENCY", _find_line(raw, f'"{dep}"'),
                                f"{'transitive' if depth else 'locked'} `{dep}@{ver}`: {adv}"))
                walk(meta.get("dependencies") or {}, depth + 1)

        if not data.get("packages"):
            walk(data.get("dependencies") or {}, 0)
    return out
