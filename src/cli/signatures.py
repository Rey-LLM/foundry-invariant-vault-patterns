"""Layer 13: the FoundryGuard signature database.

Fifteen named signatures, eight for Solidity and seven for the backend that talks to it. Each one fixes the
severity a match costs in the score (CRITICAL -25, HIGH -15), carries a CWE/SWC reference, a one-line mitigation
and a short fix example that the HTML report prints next to the hit.

The detectors themselves live where the text is parsed: Solidity rules in ``scoring.check_solidity`` (it owns the
contract/function splitter), line rules in ``scoring.LINE_RULES``, and the two file-level backend checks
(body size cap, rate limit on auth routes) below in ``check_backend``. This module never imports ``scoring``.

``foundryguard.toml`` can move a signature to another severity or switch it off::

    [score.severity]
    "FG-02" = "MEDIUM"           # by signature id
    "WEB-RATE-LIMIT" = "off"     # or by rule name; any rule FoundryGuard emits can be tuned this way
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

LAYER_ID = "L13"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
OFF = "off"


@dataclass(frozen=True)
class Signature:
    id: str
    rule: str  # the rule name findings carry
    stack: str  # "solidity" or "backend"
    severity: str
    ref: str  # CWE / SWC reference
    title: str
    mitigation: str
    fix: str  # short before/after or replacement snippet
    aliases: tuple[str, ...] = ()  # other rule names (e.g. Layer 12 bridge rules) that are the same flaw

    def as_dict(self) -> dict:
        return asdict(self)


SIGNATURES: tuple[Signature, ...] = (
    # ----------------------------------------------------------------- Solidity
    Signature("FG-01", "SOL-ZERO-ADDRESS", "solidity", "HIGH", "CWE-20 / SWC-123",
              "Address parameter stored without a zero-address check",
              "Revert on `address(0)` before storing a role, a token, a treasury or an oracle.",
              "if (newOwner == address(0)) revert ZeroAddress();\nowner = newOwner;"),
    Signature("FG-02", "SOL-DIV-BEFORE-MUL", "solidity", "HIGH", "CWE-682 / SWC-101",
              "Division before multiplication loses precision",
              "Multiply first, or use `Math.mulDiv(a, b, c)` so the intermediate keeps full precision.",
              "// was: amount / total * rate\nuint256 out = Math.mulDiv(amount, rate, total);"),
    Signature("FG-03", "SOL-TX-ORIGIN", "solidity", "CRITICAL", "CWE-477 / SWC-115",
              "Authorization through tx.origin",
              "Authorize `msg.sender`; any contract the user calls can act as them under `tx.origin`.",
              "require(msg.sender == owner, \"not owner\");"),
    Signature("FG-04", "SOL-WEAK-RANDOMNESS", "solidity", "HIGH", "CWE-330 / SWC-120",
              "Randomness derived from block values",
              "Use Chainlink VRF or commit-reveal; timestamp, prevrandao and blockhash are known to the block builder.",
              "uint256 requestId = vrfCoordinator.requestRandomWords(req);\n// use the word in fulfillRandomWords"),
    Signature("FG-05", "SOL-UNCHECKED-CALL", "solidity", "HIGH", "CWE-252 / SWC-104",
              "Low-level call or send whose result is ignored",
              "Capture the bool and revert on failure, or use `Address.sendValue` / `functionCall`.",
              "(bool ok, ) = to.call{value: amount}(\"\");\nif (!ok) revert TransferFailed();"),
    Signature("FG-06", "SOL-ERC20-UNCHECKED", "solidity", "HIGH", "CWE-252 / SWC-104",
              "ERC-20 transfer/transferFrom/approve whose bool is ignored",
              "Use OpenZeppelin `SafeERC20` (`safeTransfer`, `safeTransferFrom`, `forceApprove`); USDT-style tokens "
              "return false or nothing instead of reverting.",
              "using SafeERC20 for IERC20;\ntoken.safeTransfer(to, amount);"),
    Signature("FG-07", "SOL-ARBITRARY-FROM", "solidity", "CRITICAL", "CWE-285",
              "transferFrom pulls from a caller-chosen address",
              "Pull only from `msg.sender` (or from an address that signed a permit for this exact call); anyone "
              "can otherwise drain every wallet that approved the contract.",
              "token.safeTransferFrom(msg.sender, address(this), amount);"),
    Signature("FG-08", "SOL-UNBOUNDED-LOOP", "solidity", "HIGH", "CWE-834 / SWC-128",
              "Loop over a storage array that anyone can grow",
              "Bound the loop (paginate with start/count), or keep a running total instead of iterating; a long "
              "array pushes the call past the block gas limit and locks the function.",
              "function process(uint256 start, uint256 count) external {\n    uint256 end = Math.min(start + count, items.length);\n    for (uint256 i = start; i < end; ++i) { ... }\n}"),
    # ----------------------------------------------------------------- backend
    Signature("FG-09", "WEB-SECRET", "backend", "CRITICAL", "CWE-798",
              "Private key, API key or secret hardcoded in source",
              "Load it from the environment or a secret manager, rotate it now, and purge it from git history.",
              "PRIVATE_KEY = os.environ[\"SIGNER_KEY\"]  # never a literal",
              aliases=("BRIDGE-MNEMONIC-LITERAL", "BRIDGE-RPC-KEY")),
    Signature("FG-10", "WEB-WEAK-RANDOM", "backend", "HIGH", "CWE-338",
              "Math.random / random module used for tokens, nonces or secrets",
              "Use `crypto.randomUUID()` / `crypto.getRandomValues` in JS, `secrets` in Python, `random_bytes` in PHP.",
              "const token = crypto.randomBytes(32).toString(\"hex\");",
              aliases=("BRIDGE-WEAK-NONCE",)),
    Signature("FG-11", "WEB-BODY-LIMIT", "backend", "HIGH", "CWE-770",
              "Request body size not capped",
              "Set an explicit cap: `app.config[\"MAX_CONTENT_LENGTH\"]` in Flask, `limits: { fileSize }` in multer, "
              "a reverse-proxy `client_max_body_size` elsewhere.",
              "app.config[\"MAX_CONTENT_LENGTH\"] = 1 * 1024 * 1024  # 1 MB"),
    Signature("FG-12", "WEB-RATE-LIMIT", "backend", "HIGH", "CWE-307",
              "Login, signup, reset or OTP route with no rate limiter in the project",
              "Rate-limit credential and token routes per IP and per account (express-rate-limit, flask-limiter, "
              "slowapi) and lock out after repeated failures.",
              "limiter = Limiter(get_remote_address, app=app)\n@app.post(\"/login\")\n@limiter.limit(\"5/minute\")"),
    Signature("FG-13", "WEB-CORS-ANY", "backend", "HIGH", "CWE-942",
              "CORS allows any origin",
              "List the exact origins that may call the API; never combine `*` (or a reflected origin) with credentials.",
              "cors({ origin: [\"https://app.example.com\"], credentials: true })"),
    Signature("FG-14", "WEB-EVAL", "backend", "CRITICAL", "CWE-95",
              "eval / exec / new Function on runtime data",
              "Never evaluate strings; parse the data (`json.loads`, `JSON.parse`) and dispatch on known values.",
              "handler = HANDLERS.get(name)\nif handler is None: abort(400)"),
    Signature("FG-15", "WEB-COMMAND", "backend", "CRITICAL", "CWE-78",
              "Shell command built and executed at runtime",
              "Run the program with an argument list and no shell (`subprocess.run([...])`, `execFile`), and "
              "validate every argument against an allowlist.",
              "subprocess.run([\"ping\", \"-c\", \"1\", host], check=True, timeout=5)"),
)

BY_ID = {s.id: s for s in SIGNATURES}
BY_RULE: dict[str, Signature] = {}
for _s in SIGNATURES:
    BY_RULE[_s.rule] = _s
    for _a in _s.aliases:
        BY_RULE[_a] = _s


def lookup(rule: str) -> Signature | None:
    return BY_RULE.get(rule)


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
            if f.rule == sig.rule:
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
# File-level backend checks (FG-11, FG-12)
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


def limiter_present(raw: str) -> bool:
    return bool(RATE_LIMITER.search(raw))


def _line(raw: str, offset: int) -> int:
    return raw.count("\n", 0, offset) + 1


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
    return out
