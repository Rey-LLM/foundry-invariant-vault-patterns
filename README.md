# FoundryGuard v0.18

**Hybrid Web2/Web3 Static and Dynamic Vulnerability Assessment Platform**

FoundryGuard assesses a codebase that ships both smart contracts and the backend that drives them. It reads the Solidity through the compiler's typed AST, reads the Node and Python backend and site code as source, links the two at the signing seam, and then exercises the contracts dynamically with generated Foundry invariant suites. Every finding is tied to a file and line, mapped to one of 170 catalogued signatures with a CWE or SWC reference, weighted into a 1 to 100 risk score, and exported as HTML, Markdown, JSON and SARIF.

It is built for engineering teams assessing their own code: point it at a repository you own or have been asked to review. Remote targets are limited to one passive request, and nothing is fuzzed against a host.

| | |
| :-- | :-- |
| Version | 0.18.0 (`pyproject.toml`) |
| Runtime | Python 3.9 to 3.13; solc, solcjs or Foundry for contract analysis; Foundry for dynamic runs |
| Interfaces | CLI (`foundryguard`, `foundryguard-bridge`), desktop console (`foundryguard-gui`), GitHub Action |
| Outputs | `foundryguard-report.html`, `foundryguard-score.json`, `foundryguard-findings.log`, `FoundryGuard_Report.md`, `foundryguard.sarif` |
| Verification | 505 unit and integration tests, plus forge fuzzing of every fixture project in CI |
| License | MIT |

## Contents

- [Capabilities](#capabilities)
- [Installation and quick start](#installation-and-quick-start)
- [Command reference](#command-reference)
- [Architecture](#architecture)
- [Signature matrix: FG-01 to FG-170](#signature-matrix-fg-01-to-fg-170)
- [Risk scoring](#risk-scoring)
- [Desktop console](#desktop-console)
- [Static analysis: contract model](#static-analysis-contract-model)
- [Dynamic analysis: invariant suites](#dynamic-analysis-invariant-suites)
- [Backend-to-contract bridge validation](#backend-to-contract-bridge-validation)
- [Threat intel sync](#threat-intel-sync)
- [Reporting](#reporting)
- [Configuration](#configuration)
- [CI integration](#ci-integration)
- [Reference invariant suites](#reference-invariant-suites)
- [Verification](#verification)
- [Scope and known limitations](#scope-and-known-limitations)

## Capabilities

| Domain | Mode | What is assessed |
| :-- | :-- | :-- |
| Web3 contract safety | Static | 79 Solidity signatures (FG-01 to FG-50, FG-104 to FG-125, FG-151 to FG-157): reentrancy, price and oracle manipulation, access control, proxies and diamonds, signatures and replay, ordering, governance, arithmetic, transient storage, staking and reward accounting, timelocks, emergency exits, ERC-721 and ERC-1155 state, EIP-712 and signature-hash construction, commit-reveal, Merkle leaves |
| Web3 contract behaviour | Dynamic | Generated Foundry handlers and invariants, eight attack presets, cross-contract ecosystem suites; broken invariants are reported with the shrunk call sequence and a replay test |
| Web2 backend | Static | Injection (SQL, NoSQL, command, template, eval, headers, regex, prototype pollution), XSS, SSRF, XXE, deserialization, path traversal, IDOR on reads and writes, unauthenticated state routes, mass assignment, JWT issue and verify, session cookies and fixation, WebSocket handshakes, cache scoping, CSRF, rate limits, debug configuration |
| Cryptography | Static | 20 signatures (FG-151 to FG-170): EIP-712 domain, typehash and field encoding, unprefixed or caller-chosen signed digests, commit-reveal binding, 64-byte Merkle leaves; ECB, constant IVs and nonces, literal keys, DES/3DES/RC4, `createCipher`, weak PBKDF2/bcrypt/scrypt cost, fast password hashes, CBC without a MAC, short RSA keys, PKCS#1 v1.5 encryption, JWT algorithm confusion and decode-only, legacy TLS |
| Secrets and data exposure | Static | Hardcoded keys and secrets, key material written to logs or responses, signing keys shipped to the browser, tokens in `localStorage`, version banners |
| HTTP surface | Passive | One GET per URL: CSP, HSTS, framing, nosniff, cookie flags, CORS, mixed content |
| Supply chain | Static | `package.json`, `package-lock.json` (transitive) and `requirements*.txt` against a bundled advisory list, plus OSV ranges when the intel sync is on |
| Threat intel sync | Network, optional | Extra line rules (SWC, CWE, CVE) and dependency advisories pulled from public feeds and merged in memory; every entry is checked before use |
| Web2 to Web3 bridge | Static | Signing oracles, open relayers, EIP-712 typehash and domain drift, replay, unenforced deadlines, ABI drift, nonce races, reorg handling |
| Self-healing build | Compile loop | Generated suites recompiled and repaired against the project's own compiler |

## Installation and quick start

```sh
pipx install git+https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git

foundryguard score .                  # static assessment, 1-100 score, foundryguard-report.html
foundryguard score . --fuzz           # add the dynamic pass (requires forge and a foundry.toml)
foundryguard bridge .                 # backend-to-contract seam only
foundryguard run --test               # generate invariant suites, run forge, write FoundryGuard_Report.md
foundryguard-gui                      # desktop console
```

`pipx install` places `foundryguard`, `foundryguard-gui` and `foundryguard-bridge` on `PATH`. Without installing, run `python3 path/to/src/cli/foundryguard.py`. Python 3.9 and 3.10 also need `tomli`, which the package installs. Contract analysis needs a Solidity compiler (solc, solcjs or Foundry); the dynamic pass needs [Foundry](https://getfoundry.sh/introduction/installation/).

## Command reference

| Command | What it does |
| :-- | :-- |
| `foundryguard init` | writes a commented `foundryguard.toml` into the project root (the nearest folder with `foundry.toml`, `.git`, `package.json` or `pyproject.toml`) |
| `foundryguard scan` | Solidity to a `foundryguard.json` blueprint |
| `foundryguard gen` | blueprint to `test/foundryguard/<Contract>/` and `test/foundryguard/<Name>Ecosystem/` suites |
| `foundryguard run [--test]` | `scan` and `gen`; with `--test` also `forge test` and the report |
| `foundryguard check` | exits 1 when generated suites are missing or stale |
| `foundryguard heal` | compiles the generated suites and fixes what the local compiler rejects |
| `foundryguard report <file or ->` | `forge test --json` or `-vvv` output to `FoundryGuard_Report.md` and `foundryguard-report.html`, plus CI Markdown and SARIF |
| `foundryguard score <path or URL>` | risk score from 1 to 100 with a deduction per file and line, written to `foundryguard-report.html` |
| `foundryguard intel sync` / `status` | fetch the dynamic signatures now, or show what the cache holds |
| `foundryguard bridge <path>` | the seam between backend and contracts: who can make the server key sign or send, and whether the contract enforces what the backend signs |
| `foundryguard-gui [path or URL]` | desktop window that runs the score, the preset matrix and, with forge installed, the fuzzing (`foundryguard gui` does the same) |

## Architecture

FoundryGuard is a layered pipeline. Each layer is a separate module under `src/cli/` with its own tests.

| Layer | Module | What it does |
| :-- | :-- | :-- |
| 01 | `parser.py` | reads the contracts and classifies value flows into a blueprint |
| 02 | `injector.py` | writes handlers and invariant suites (Presets 01-03 inline) |
| 03 | `compiler.py` | drives solc, solcjs or forge for the AST |
| 04 | `blueprints/hook_reentrancy.py`, `reporter.py` | hook read-reentrancy probe; forge output to a report |
| 05 | `blueprints/transient_storage.py` | transient slots checked between calls |
| 06 | `ai_generator.py` | opt-in model fallback for contracts no preset fits |
| 07 | `parser.py`, `injector.py` | cross-contract ecosystems and deploy order |
| 08 | `healer.py` | compiles generated suites and fixes what the compiler rejects |
| 09 | `reporter.py` | static HTML report |
| 10 | `scoring.py`, `gui.py` | 1-100 score, preset matrix, desktop window |
| 11 | `scoring.py` | backend and site code rules |
| 12 | `web_surface.py` | backend to contract bridge |
| 13 | `signatures.py` | the signature database (FG-01 to FG-170 since 0.18) |
| 17 | `intel_sync.py` | threat intel sync |
| 18 | `scoring.py`, `signatures.py` | cryptography misuse (FG-151 to FG-170) |

```text
src/cli/
  foundryguard.py      command line entry point
  compiler.py          solc / solcjs / forge drivers, Standard JSON, remappings
  parser.py            compact AST to blueprint, value-flow classification, dependency matrix
  injector.py          handler and invariant suite generation, ecosystem suites
  blueprints/          Preset 04 (hook_reentrancy.py) and Preset 05 (transient_storage.py)
  ai_generator.py      opt-in model fallback for contracts no preset covers
  healer.py            compile-and-repair loop for generated suites
  reporter.py          forge output to Markdown, HTML and SARIF
  scoring.py           static rules, 1-100 score, simulation matrix
  web_surface.py       backend-to-contract bridge validator
  signatures.py        FG-01 to FG-170 signature catalogue
  gui.py               desktop console
tests/foundryguard/    unit and integration tests, weak/safe fixture pairs per layer
src/, test/            reference contracts and invariant suites (see below)
```

## Signature matrix: FG-01 to FG-170

The signature database (`src/cli/signatures.py`) defines 170 distinct failure modes. Ids only grow: 0.16 appended FG-104 to FG-150, 0.18 appended FG-151 to FG-170, and earlier ids keep their meaning. Each carries a fixed severity, a CWE or SWC reference, a one-line mitigation and a fix example that the HTML report prints next to the hit. Every finding in the report and in `--json` output carries its signature id.

| Range | Surface | Stacks | Count |
| :-- | :-- | :-- | --: |
| FG-01 to FG-50 | Web3 | Solidity | 50 |
| FG-51 to FG-83 | Web2 | Backend source (`.py`, `.js`, `.ts`, `.html`, `.php`), one HTTP signature (FG-79) | 33 |
| FG-84 to FG-89 | Web2 | HTTP response headers | 6 |
| FG-90 | Web2 | Dependency manifests | 1 |
| FG-91 to FG-103 | Web2 to Web3 | Backend-to-contract bridge | 13 |
| FG-104 to FG-125 | Web3 | Solidity: staking, rewards, timelocks, emergency exits, NFTs | 22 |
| FG-126 to FG-150 | Web2 | Backend source: API state routes, WebSockets, headers, caching, sessions, tokens, GraphQL | 25 |
| FG-151 to FG-157 | Web3 | Solidity: EIP-712, signed digests, commit-reveal, Merkle leaves | 7 |
| FG-158 to FG-170 | Web2 | Backend source: ciphers, IVs, keys, KDFs, password hashing, RSA, JWT algorithms, TLS versions | 13 |

Secrets and data-exposure coverage spans the backend and bridge groups: FG-51 (hardcoded keys, API keys, salts and secrets), FG-74 (auth tokens in `localStorage`), FG-75 (session cookies without `Secure`/`HttpOnly`), FG-89 (version disclosure), FG-94 to FG-96 (key material read from requests, written to logs or responses, or shipped to the browser).

### Web3 contract safety (FG-01 to FG-50)

#### Input validation, arithmetic and precision

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-01 | Solidity | `SOL-ZERO-ADDRESS` | HIGH | CWE-20 / SWC-123 | Address parameter stored without a zero-address check |
| FG-02 | Solidity | `SOL-DIV-BEFORE-MUL` | HIGH | CWE-682 / SWC-101 | Division before multiplication loses precision |
| FG-45 | Solidity | `SOL-INPUT-VALIDATION` | HIGH | CWE-20 | External function takes input and never validates any of it |
| FG-46 | Solidity | `SOL-DIV-BY-TOTAL` | MEDIUM | CWE-369 | Division by a total that can be zero |
| FG-47 | Solidity | `SOL-UNSAFE-DOWNCAST` | MEDIUM | CWE-681 / SWC-101 | Integer downcast without a bound check |
| FG-48 | Solidity | `SOL-NO-OVERFLOW-CHECKS` | HIGH | SWC-101 / CWE-190 | Compiler before 0.8 and arithmetic without SafeMath |
| FG-49 | Solidity | `SOL-UNCHECKED-MATH` | LOW | CWE-190 | Subtraction or multiplication inside unchecked |

#### Authorization and privileged state

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-03 | Solidity | `SOL-TX-ORIGIN` | CRITICAL | CWE-477 / SWC-115 | Authorization through tx.origin |
| FG-19 | Solidity | `SOL-UNPROTECTED-MUTATION` | CRITICAL | CWE-284 / SWC-105 | Privileged state writable by anyone |
| FG-20 | Solidity | `SOL-UNGUARDED-INITIALIZER` | CRITICAL | CWE-665 | Initializer without an initializer lock (can be called again) |
| FG-21 | Solidity | `SOL-IMPL-NOT-DISABLED` | HIGH | CWE-665 | Upgradeable implementation left uninitialized |
| FG-22 | Solidity | `SOL-UUPS-NO-AUTH` | CRITICAL | CWE-284 | UUPS `_authorizeUpgrade` with no access check |

#### Reentrancy and external calls

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-05 | Solidity | `SOL-UNCHECKED-CALL` | HIGH | CWE-252 / SWC-104 | Low-level call or send whose result is ignored |
| FG-06 | Solidity | `SOL-ERC20-UNCHECKED` | HIGH | CWE-252 / SWC-104 | ERC-20 transfer/transferFrom/approve whose bool is ignored |
| FG-07 | Solidity | `SOL-ARBITRARY-FROM` | CRITICAL | CWE-285 | transferFrom pulls from a caller-chosen address |
| FG-09 | Solidity | `SOL-CEI-DRIFT` | HIGH | CWE-841 / SWC-107 | Reentrancy: state written after an external call |
| FG-10 | Solidity | `SOL-READONLY-REENTRANCY` | HIGH | CWE-841 / SWC-107 | View function exposes state that is stale during an external call |
| FG-26 | Solidity | `SOL-DELEGATECALL` | CRITICAL | SWC-112 / CWE-829 | delegatecall into a variable or caller-supplied target |
| FG-27 | Solidity | `SOL-ARBITRARY-CALL` | CRITICAL | CWE-749 | Caller chooses both the target and the calldata of an external call |
| FG-36 | Solidity | `SOL-GAS-STIPEND` | MEDIUM | SWC-134 / CWE-400 | Ether sent with a fixed gas stipend (transfer/send/gas: N) |
| FG-37 | Solidity | `SOL-SHORT-CALLDATA` | MEDIUM | CWE-130 | Calldata decoded by hand without a length check (short address) |

#### Price, oracle and balance manipulation

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-11 | Solidity | `SOL-SPOT-PRICE` | HIGH | CWE-807 | Price read from a pool's spot reserves (flash-loan manipulable) |
| FG-12 | Solidity | `SOL-DONATION-DRIFT` | MEDIUM | CWE-682 | Accounting reads the contract's own balance (donation manipulable) |
| FG-13 | Solidity | `SOL-SHARE-INFLATION` | HIGH | CWE-1339 | First-depositor share inflation (no virtual offset) |
| FG-15 | Solidity | `SOL-TWAP-SHORT-WINDOW` | HIGH | CWE-807 | TWAP window shorter than 30 minutes (TWAP squeeze) |
| FG-16 | Solidity | `SOL-STALE-ORACLE` | MEDIUM | CWE-672 | Oracle answer used without a staleness check |
| FG-17 | Solidity | `SOL-ORACLE-BAD-PRICE` | MEDIUM | CWE-20 | Oracle answer cast to uint without checking it is positive |

#### Upgradeability, proxies and diamonds

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-23 | Solidity | `SOL-PROXY-STORAGE-COLLISION` | CRITICAL | SWC-124 / CWE-123 | Proxy declares its own storage variables (slot collision) |
| FG-24 | Solidity | `SOL-DIAMOND-SLOT-REUSE` | CRITICAL | SWC-124 / CWE-694 | Two diamond storage structs hashed to the same slot |
| FG-25 | Solidity | `SOL-STORAGE-GAP` | MEDIUM | SWC-124 | Upgradeable base contract with state but no storage gap |
| FG-28 | Solidity | `SOL-SELFDESTRUCT` | HIGH | SWC-106 / CWE-284 | selfdestruct in deployed code |

#### Signatures and replay

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-29 | Solidity | `SOL-SIG-MALLEABLE` | MEDIUM | SWC-117 / CWE-347 | Raw ecrecover accepts malleable (high-s) signatures |
| FG-30 | Solidity | `BRIDGE-RAW-ECRECOVER` | MEDIUM | SWC-122 / CWE-252 | ecrecover result not checked against address(0) |
| FG-31 | Solidity | `BRIDGE-SIG-REPLAY` | HIGH | SWC-121 / CWE-294 | Signature can be submitted again (no nonce consumed) |
| FG-32 | Solidity | `BRIDGE-SIG-NO-DOMAIN` | HIGH | SWC-121 / CWE-294 | Signature not bound to chain id and contract (cross-chain replay) |
| FG-33 | Solidity | `BRIDGE-PACKED-COLLISION` | MEDIUM | SWC-133 / CWE-328 | abi.encodePacked with two dynamic values in a signed hash |
| FG-34 | Solidity | `BRIDGE-SIG-NO-EXPIRY` | LOW | CWE-613 | Accepted signatures never expire |

#### Transient storage

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-18 | Solidity | `SOL-TRANSIENT-LEAK` | HIGH | CWE-459 | Transient storage slot set and never cleared |

#### Ordering, MEV and time

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-04 | Solidity | `SOL-WEAK-RANDOMNESS` | HIGH | CWE-330 / SWC-120 | Randomness derived from block values |
| FG-35 | Solidity | `SOL-TIMESTAMP-EQUALITY` | MEDIUM | SWC-116 / CWE-829 | Logic depends on block.timestamp hitting an exact value |
| FG-38 | Solidity | `SOL-DIRTY-ORDER` | HIGH | CWE-841 | Order executed without checking it is still open |
| FG-39 | Solidity | `SOL-SLIPPAGE-ZERO` | HIGH | CWE-20 | Swap with a minimum output of zero (sandwichable) |
| FG-40 | Solidity | `SOL-DEADLINE-NOW` | MEDIUM | CWE-20 | Swap deadline set to block.timestamp (no deadline) |

#### Governance and voting

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-14 | Solidity | `SOL-FLASH-VOTE` | HIGH | CWE-807 | Votes weighed by live balance (flash-loan votes) |
| FG-41 | Solidity | `SOL-VOTE-DOUBLE-COUNT` | HIGH | CWE-837 | Vote tally increased without a has-voted check |
| FG-42 | Solidity | `SOL-DELEGATE-INFLATION` | HIGH | CWE-682 | Delegation adds voting weight without removing it from the old delegate |

#### Denial of service and reward accounting

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-08 | Solidity | `SOL-UNBOUNDED-LOOP` | HIGH | CWE-834 / SWC-128 | Loop over a storage array that anyone can grow |
| FG-43 | Solidity | `SOL-ETH-PUSH-LOOP` | HIGH | SWC-113 / CWE-703 | Ether pushed to many recipients in one loop |
| FG-44 | Solidity | `SOL-MSG-VALUE-LOOP` | HIGH | CWE-837 | msg.value read inside a loop (or a payable multicall) |
| FG-50 | Solidity | `SOL-UNFUNDED-REWARDS` | HIGH | CWE-682 | Reward rate set without checking the tokens are there |

### Web3 staking, rewards, timelocks and NFT state (FG-104 to FG-125, since 0.16)

#### Staking locks and reward accounting

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-104 | Solidity | `SOL-STAKE-NO-LOCK` | HIGH | CWE-841 | Stake withdrawable before its lock period ends |
| FG-105 | Solidity | `SOL-REWARD-NOT-UPDATED` | HIGH | CWE-682 | Staked balance changes without settling rewards first |
| FG-106 | Solidity | `SOL-REWARD-PRECISION` | MEDIUM | CWE-1339 | Reward-per-token accumulator divides without a scale factor |
| FG-107 | Solidity | `SOL-REWARD-LOOP-DISTRIBUTION` | HIGH | CWE-834 | Rewards pushed pro-rata to every staker in one loop |
| FG-120 | Solidity | `SOL-REWARD-CLAIM-NO-RESET` | CRITICAL | CWE-841 | Reward claim pays out without zeroing the owed amount |
| FG-121 | Solidity | `SOL-REWARD-PERIOD-OVERWRITE` | HIGH | CWE-682 | New reward period overwrites the rate and drops the unpaid remainder |
| FG-122 | Solidity | `SOL-LOCK-GRIEFING` | MEDIUM | CWE-284 | Anyone can extend another user's lock by depositing for them |
| FG-123 | Solidity | `SOL-VESTING-OVERRUN` | HIGH | CWE-682 | Linear vesting keeps growing after the end date |

#### Emergency exits, rescues and timelocks

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-108 | Solidity | `SOL-EMERGENCY-WITHDRAW-FLAW` | HIGH | CWE-841 | Emergency withdraw pays rewards or leaves the stake on the books |
| FG-109 | Solidity | `SOL-RESCUE-DRAINS-STAKE` | HIGH | CWE-284 | Admin token rescue can pull the users' staked token |
| FG-110 | Solidity | `SOL-NO-TIMELOCK` | MEDIUM | CWE-284 | Fee changed instantly by the admin with no cap and no timelock |
| FG-111 | Solidity | `SOL-TIMELOCK-BYPASS` | CRITICAL | CWE-863 | Queued action executable before its ETA |
| FG-112 | Solidity | `SOL-TIMELOCK-SHORT-DELAY` | MEDIUM | CWE-1188 | Timelock delay shorter than one day |
| FG-125 | Solidity | `SOL-EMERGENCY-PAUSED` | MEDIUM | CWE-400 | Emergency exit disabled while the contract is paused |

#### ERC-721 and ERC-1155 state

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-113 | Solidity | `SOL-NFT-UNSAFE-MINT` | LOW | CWE-20 | ERC-721 minted with _mint to a caller-chosen address |
| FG-114 | Solidity | `SOL-NFT-HOOK-REENTRANCY` | HIGH | CWE-841 / SWC-107 | State written after _safeMint / safeTransferFrom (receiver hook reentrancy) |
| FG-115 | Solidity | `SOL-NFT-STAKE-RECORD-DRIFT` | HIGH | CWE-672 | Staked NFT returned while its staker record stays set |
| FG-116 | Solidity | `SOL-NFT-UNSTAKE-ANY` | CRITICAL | CWE-639 | Anyone can withdraw a staked NFT (no owner check) |
| FG-117 | Solidity | `SOL-ARRAY-LENGTH-MISMATCH` | MEDIUM | CWE-130 | Parallel arrays (ids/amounts) used without a length check |
| FG-118 | Solidity | `SOL-SUPPLY-DRIFT` | MEDIUM | CWE-682 | Per-id supply counter raised on mint and never lowered on burn |
| FG-119 | Solidity | `SOL-NFT-APPROVAL-STALE` | HIGH | CWE-284 | Hand-written ERC-721 transfer keeps the previous owner's approval |
| FG-124 | Solidity | `SOL-RECEIVER-ANY-TOKEN` | HIGH | CWE-345 | onERC721Received / onERC1155Received credits a deposit from any token contract |

### Web2 backend, HTTP surface and bridge (FG-51 to FG-103)

#### Injection and unsafe execution (backend)

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-56 | Backend | `WEB-EVAL` | CRITICAL | CWE-95 | eval / exec / new Function on runtime data |
| FG-57 | Backend | `WEB-COMMAND` | CRITICAL | CWE-78 | Shell command built and executed at runtime |
| FG-58 | Backend | `WEB-SQL` | CRITICAL | CWE-89 | SQL built from strings |
| FG-59 | Backend | `WEB-NOSQL` | HIGH | CWE-943 | NoSQL query built from the raw request object (operator injection) |
| FG-60 | Backend | `WEB-SSTI` | CRITICAL | CWE-1336 | Template rendered from a string that contains request data |
| FG-61 | Backend | `WEB-XSS` | HIGH | CWE-79 | Untrusted HTML written into the page |
| FG-62 | Backend | `WEB-SSRF` | HIGH | CWE-918 | Server fetches a URL taken from the request |
| FG-63 | Backend | `WEB-XXE` | HIGH | CWE-611 | XML parser resolves external entities |
| FG-64 | Backend | `WEB-DESERIALIZE` | HIGH | CWE-502 | Insecure deserialization of untrusted data |
| FG-65 | Backend | `WEB-PATH-TRAVERSAL` | HIGH | CWE-22 | File path taken from the request |
| FG-66 | Backend | `WEB-OPEN-REDIRECT` | MEDIUM | CWE-601 | Redirect target taken from the request |

#### Input handling, authorization and session security (backend)

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-53 | Backend | `WEB-BODY-LIMIT` | HIGH | CWE-770 | Request body size not capped |
| FG-54 | Backend | `WEB-RATE-LIMIT` | HIGH | CWE-307 | Login, signup, reset or OTP route with no rate limiter in the project |
| FG-67 | Backend | `WEB-INPUT-VALIDATION` | HIGH | CWE-20 | Request input used with no validation layer in the file |
| FG-68 | Backend | `WEB-MASS-ASSIGNMENT` | HIGH | CWE-915 | Whole request body written into a model (parameter contamination) |
| FG-69 | Backend | `WEB-IDOR` | HIGH | CWE-639 | Record loaded by an id from the URL with no ownership check (BOLA/IDOR) |
| FG-70 | Backend | `WEB-JWT-NONE` | HIGH | CWE-347 | JWT signature or expiry not verified |
| FG-71 | Backend | `WEB-TIMING-COMPARE` | MEDIUM | CWE-208 | Secret, token or signature compared with == (timing leak) |
| FG-72 | Backend | `WEB-TOKEN-ENTROPY` | MEDIUM | CWE-331 | Token with too little entropy (short or time-based) |
| FG-74 | Backend | `WEB-TOKEN-STORAGE` | MEDIUM | CWE-922 | Auth token kept in localStorage |
| FG-75 | Backend | `WEB-COOKIE-INSECURE` | MEDIUM | CWE-614 / CWE-1004 | Session cookie missing Secure or HttpOnly |
| FG-76 | Backend | `WEB-CSRF` | MEDIUM | CWE-352 | POST form without an anti-CSRF token |
| FG-82 | Backend | `WEB-GLOBAL-STATE` | MEDIUM | CWE-362 | Request handler mutates module-level state (race) |

#### Secrets, cryptography and transport (backend)

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-51 | Backend | `WEB-SECRET` | CRITICAL | CWE-798 | Private key, API key, salt or secret hardcoded in source |
| FG-52 | Backend | `WEB-WEAK-RANDOM` | HIGH | CWE-338 | Math.random / random module used for tokens, nonces or secrets |
| FG-73 | Backend | `WEB-WEAK-HASH` | LOW | CWE-328 | MD5 or SHA-1 in use |
| FG-77 | Backend | `WEB-TLS-OFF` | HIGH | CWE-295 | TLS certificate checks disabled |
| FG-78 | Backend | `WEB-PLAIN-HTTP` | MEDIUM | CWE-319 | Plain http:// endpoint or page |
| FG-80 | Backend | `WEB-NO-SRI` | LOW | CWE-353 | Third-party script without an integrity hash |
| FG-81 | Backend | `WEB-DEBUG` | MEDIUM | CWE-489 | Debug mode enabled |
| FG-83 | Backend | `WEB-NO-HEADERS-MW` | MEDIUM | CWE-693 | App sets no security headers (no helmet / Talisman) |

#### HTTP response surface

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-55 | Backend | `WEB-CORS-ANY` | HIGH | CWE-942 | CORS allows any origin |
| FG-79 | HTTP headers | `WEB-MIXED-CONTENT` | MEDIUM | CWE-319 | http:// resource loaded by an https page |
| FG-84 | HTTP headers | `URL-NO-CSP` | HIGH | CWE-693 | No Content-Security-Policy header |
| FG-85 | HTTP headers | `URL-WEAK-CSP` | MEDIUM | CWE-693 | CSP allows unsafe-inline or unsafe-eval |
| FG-86 | HTTP headers | `URL-NO-HSTS` | MEDIUM | CWE-319 | No Strict-Transport-Security header |
| FG-87 | HTTP headers | `URL-NO-NOSNIFF` | LOW | CWE-693 | No X-Content-Type-Options: nosniff |
| FG-88 | HTTP headers | `URL-CLICKJACKING` | MEDIUM | CWE-1021 | Page can be framed by any site |
| FG-89 | HTTP headers | `URL-VERSION-LEAK` | LOW | CWE-200 | Server or X-Powered-By header discloses a version |

#### Supply chain

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-90 | Dependencies | `WEB-VULN-DEPENDENCY` | HIGH | CWE-1395 | Dependency (direct or transitive) pinned to a version with a known advisory |

#### Backend-to-contract bridge

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-91 | Bridge | `BRIDGE-SIGNING-ORACLE` | CRITICAL | CWE-306 | Public route signs with the server key for any caller |
| FG-92 | Bridge | `BRIDGE-OPEN-RELAYER` | CRITICAL | CWE-306 | Public route sends transactions from the server key for any caller |
| FG-93 | Bridge | `BRIDGE-SIGNED-INPUT-UNCHECKED` | HIGH | CWE-20 | Request values signed without bounds |
| FG-94 | Bridge | `BRIDGE-KEY-FROM-REQUEST` | CRITICAL | CWE-522 | Private key or mnemonic read from the request |
| FG-95 | Bridge | `BRIDGE-KEY-LOGGED` | HIGH | CWE-532 | Key material written to a log or response |
| FG-96 | Bridge | `BRIDGE-KEY-CLIENT` | CRITICAL | CWE-312 | Signing key shipped to the browser |
| FG-97 | Bridge | `BRIDGE-TX-NONCE-RACE` | MEDIUM | CWE-362 | Transaction nonce read and set by hand without a lock |
| FG-98 | Bridge | `BRIDGE-RECEIPT-STATUS` | HIGH | CWE-252 | Transaction receipt used without checking status |
| FG-99 | Bridge | `BRIDGE-REORG` | MEDIUM | CWE-345 | Chain events acted on with no confirmation depth |
| FG-100 | Bridge | `BRIDGE-ABI-DRIFT` | MEDIUM | CWE-628 | Backend calls a contract function that does not match the ABI |
| FG-101 | Bridge | `BRIDGE-TYPEHASH-DRIFT` | HIGH | CWE-347 | Backend EIP-712 struct differs from the contract typehash |
| FG-102 | Bridge | `BRIDGE-DOMAIN-DRIFT` | MEDIUM | CWE-347 | Backend EIP-712 domain differs from the contract |
| FG-103 | Bridge | `BRIDGE-DEADLINE-UNENFORCED` | HIGH | CWE-613 | Backend signs an expiry the contract never checks |

### Web2 API, WebSocket, caching and session security (FG-126 to FG-150, since 0.16)

#### API state endpoints and injection through headers

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-126 | Backend | `WEB-IDOR-MUTATION` | HIGH | CWE-639 | Record updated or deleted by a URL id with no ownership check |
| FG-147 | Backend | `WEB-API-STATE-NO-AUTH` | HIGH | CWE-306 | State-changing API route in a file with no authentication |
| FG-130 | Backend | `WEB-HEADER-INJECTION` | HIGH | CWE-113 | Response header value taken from the request (header injection) |
| FG-131 | Backend | `WEB-LOG-INJECTION` | LOW | CWE-117 | Raw request values written to the log |
| FG-134 | Backend | `WEB-CACHE-POISON-HOST` | MEDIUM | CWE-349 | Response built from X-Forwarded-Host (web cache poisoning) |
| FG-141 | Backend | `WEB-HOST-HEADER-LINK` | HIGH | CWE-640 | Reset or verification link built from the Host header |
| FG-142 | Backend | `WEB-REGEX-INJECTION` | MEDIUM | CWE-1333 | Regular expression built from request data (ReDoS) |
| FG-143 | Backend | `WEB-PROTOTYPE-POLLUTION` | HIGH | CWE-1321 | Request data deep-merged into an object (prototype pollution) |
| FG-144 | Backend | `WEB-UPLOAD-FILENAME` | HIGH | CWE-434 | Uploaded file saved under the client's filename |
| FG-148 | Backend | `WEB-ERROR-LEAK` | MEDIUM | CWE-209 | Exception message or stack trace returned to the client |

#### WebSockets

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-127 | Backend | `WEB-WS-NO-ORIGIN` | HIGH | CWE-1385 | WebSocket server accepts any Origin (cross-site WebSocket hijacking) |
| FG-128 | Backend | `WEB-WS-NO-AUTH` | HIGH | CWE-306 | WebSocket connection handled without authenticating the client |
| FG-129 | Backend | `WEB-WS-UNBOUNDED-MESSAGE` | MEDIUM | CWE-770 | WebSocket server with no message size limit |
| FG-150 | Backend | `WEB-WS-PLAINTEXT` | MEDIUM | CWE-319 | WebSocket endpoint over plain ws:// |

#### Caching, CORS and GraphQL

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-132 | Backend | `WEB-CACHE-PUBLIC-AUTH` | HIGH | CWE-524 | Authenticated response marked cacheable by shared caches |
| FG-133 | Backend | `WEB-CACHE-KEY-NO-USER` | HIGH | CWE-524 | Per-user response cached under a key without the user |
| FG-149 | Backend | `WEB-CORS-REFLECT` | HIGH | CWE-942 | CORS reflects the caller's Origin |
| FG-145 | Backend | `WEB-GRAPHQL-INTROSPECTION` | LOW | CWE-200 | GraphQL introspection or GraphiQL switched on |
| FG-146 | Backend | `WEB-GRAPHQL-NO-LIMIT` | MEDIUM | CWE-770 | GraphQL server with no query depth or cost limit |

#### Sessions and tokens

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-135 | Backend | `WEB-SESSION-COOKIE-CONFIG` | MEDIUM | CWE-614 | Session middleware leaves its cookie without Secure or HttpOnly |
| FG-136 | Backend | `WEB-SAMESITE-NONE` | MEDIUM | CWE-1275 | Session cookie sent cross-site (SameSite=None) |
| FG-137 | Backend | `WEB-SESSION-FIXATION` | HIGH | CWE-384 | Login stores the user in the session without regenerating its id |
| FG-138 | Backend | `WEB-JWT-NO-EXPIRY` | MEDIUM | CWE-613 | JWT issued without an expiry |
| FG-139 | Backend | `WEB-JWT-WEAK-SECRET` | HIGH | CWE-521 | JWT signed or verified with a short literal secret |
| FG-140 | Backend | `WEB-PASSWORD-PLAINTEXT` | CRITICAL | CWE-256 | Password from the request stored without hashing |

### Cryptography (FG-151 to FG-170, since 0.18)

Static checks for cryptographic misuse on both sides. They read source, never a running service.

#### Contract side: signatures, hashes and commitments

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-151 | Solidity | `SOL-EIP712-CACHED-DOMAIN` | MEDIUM | SWC-121 / CWE-294 | EIP-712 domain separator fixed at deploy, or a literal chain id in it (replayable on a fork) |
| FG-152 | Solidity | `SOL-EIP712-TYPEHASH-MISMATCH` | HIGH | CWE-347 | Struct hash encodes a different number of fields than its typehash declares |
| FG-153 | Solidity | `SOL-EIP712-DYNAMIC-UNHASHED` | MEDIUM | CWE-347 | `string`, `bytes` or array field encoded raw instead of hashed |
| FG-154 | Solidity | `SOL-SIG-UNPREFIXED-HASH` | MEDIUM | CWE-347 | Signer recovered from a bare hash with no EIP-191 or EIP-712 prefix in the file |
| FG-155 | Solidity | `SOL-SIG-CALLER-DIGEST` | HIGH | CWE-347 | Signature checked over a `bytes32` digest the caller passes in |
| FG-156 | Solidity | `SOL-COMMIT-NO-SENDER` | MEDIUM | SWC-114 / CWE-362 | Commit-reveal hash that does not include `msg.sender` (front-run copy of the reveal) |
| FG-157 | Solidity | `SOL-MERKLE-LEAF-64` | MEDIUM | CWE-328 | Merkle leaf hashed once over 64 bytes (inner node passes as a leaf) |

#### Web side: ciphers, keys, password storage, tokens and transport

| ID | Stack | Rule | Severity | Ref | Catches |
| :-- | :-- | :-- | :-- | :-- | :-- |
| FG-158 | Backend | `WEB-CIPHER-ECB` | HIGH | CWE-327 | Block cipher in ECB mode |
| FG-159 | Backend | `WEB-STATIC-IV` | HIGH | CWE-329 / CWE-323 | Constant IV or nonce passed to a cipher (zero buffer, literal, fixed bytes) |
| FG-160 | Backend | `WEB-HARDCODED-CRYPTO-KEY` | CRITICAL | CWE-321 | Cipher or HMAC key written as a literal in the call |
| FG-161 | Backend | `WEB-WEAK-CIPHER` | HIGH | CWE-327 | DES, 3DES, RC4, RC2, Blowfish, CAST, IDEA, SEED, mcrypt |
| FG-162 | Backend | `WEB-CREATECIPHER-NO-IV` | HIGH | CWE-329 / CWE-916 | Node `crypto.createCipher` (MD5 key derivation, no IV; removed in Node 22) |
| FG-163 | Backend | `WEB-WEAK-KDF` | MEDIUM | CWE-916 | PBKDF2 under 100,000 iterations, bcrypt cost under 10, scrypt N under 16,384 |
| FG-164 | Backend | `WEB-PASSWORD-FAST-HASH` | HIGH | CWE-916 | Password hashed with MD5, SHA-1, SHA-2, SHA-3 or BLAKE2 |
| FG-165 | Backend | `WEB-UNAUTHENTICATED-ENCRYPTION` | MEDIUM | CWE-649 | CBC/CTR/CFB/OFB in a file with no MAC, tag or AEAD (padding oracle, bit flipping) |
| FG-166 | Backend | `WEB-RSA-WEAK-KEY` | HIGH | CWE-326 | RSA or DSA key generated under 2048 bits |
| FG-167 | Backend | `WEB-RSA-PKCS1V15-ENCRYPT` | MEDIUM | CWE-780 | RSA encryption with PKCS#1 v1.5 padding (Bleichenbacher) |
| FG-168 | Backend | `WEB-JWT-ALG-CONFUSION` | HIGH | CWE-347 / CWE-327 | JWT verify allows HMAC and public-key algorithms together |
| FG-169 | Backend | `WEB-JWT-DECODE-ONLY` | HIGH | CWE-347 | Server reads JWT claims with `decode()` and never verifies them |
| FG-170 | Backend | `WEB-LEGACY-TLS` | MEDIUM | CWE-327 | SSLv3, TLS 1.0/1.1, or a NULL/EXPORT/RC4 cipher suite |

Related checks that predate 0.18 stay where they were: FG-29 to FG-34 (malleability, `ecrecover` zero result, replay, chain binding, packed collisions, expiry), FG-51 (secrets), FG-52 and FG-72 (weak randomness and short tokens), FG-70 and FG-139 (JWT `none` and weak secrets), FG-73 (MD5/SHA-1 anywhere), FG-77 (TLS verification off).

### Severity, aliases and numbering

Costs follow the score: CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3, with the three-hits-per-rule cap. Some rules have aliases that count as the same signature: the Layer 12 seed-phrase and RPC-key rules count as FG-51, weak signature nonces as FG-52, a server signature with no nonce as FG-31, an unbound server signature as FG-32, and the URL-mode CORS, plain-http and cookie checks as FG-55, FG-78 and FG-75. FG-26 keeps the severity its detector picks (CRITICAL for a caller-supplied target, MEDIUM otherwise).

In 0.15 the seven backend signatures that were FG-09 to FG-15 moved to FG-51 to FG-57, so a `foundryguard.toml` that tunes them by id needs the new ids; tuning by rule name is unchanged.

The report lists matched signatures first with their locations and fix, then the whole database in two collapsible tables, one per surface.

### Detector precision

What the more specific detectors look at, and what they deliberately leave alone:

* FG-10 read-only reentrancy: a public view that returns a variable some entry point writes after an external call, even under `nonReentrant`. A view that checks the lock is fine.
* FG-15 TWAP window: literal windows or `*PERIOD`/`*WINDOW`/`*TWAP*` constants under 30 minutes in a contract that calls `consult`/`observe`.
* FG-21 uninitialized implementation: a deployable contract with a public `initializer` function and no `_disableInitializers()`.
* FG-24 diamond slots: the same namespace string hashed under two different constant names anywhere in the scanned tree. EIP-1967 slot strings are skipped.
* FG-29 malleability only fires when replay protection is keyed on the signature bytes; a consumed nonce makes high-s signatures harmless.
* FG-37 short calldata: assembly `calldataload` at a fixed offset with no `calldatasize()` / `msg.data.length` check anywhere in the contract. Solidity's ABI decoder already rejects short calldata.
* FG-47 downcast: only a 256-bit parameter of an external function cast down with no comparison on it.
* FG-48: a pragma that can only resolve below 0.8 (`^0.6.12`, `=0.7.6`; not `>=0.5.0`) and arithmetic with no SafeMath.
* FG-62 SSRF: a request value reaching `requests`/`httpx`/`urlopen`/`fetch`/`axios`/`got`/`http.get` directly or through one variable.
* FG-69 IDOR: `findById(req.params.id)`, `get_or_404(id)` and similar in a file that never mentions an owner, the current user or a 403.
* FG-83 headers: an Express or Flask app with no helmet, Talisman or header code anywhere in the project.
* FG-90 dependencies: `package.json` exact, `^` and `~` pins that cannot reach the fixed version, every entry in `package-lock.json` (transitive ones included) and `==` pins in `requirements*.txt`, against a short offline list (lodash, minimist, jsonwebtoken, axios, node-fetch, express, jquery, handlebars, serialize-javascript, PyYAML, requests, Jinja2, urllib3, Flask, Werkzeug). It is a floor, not a replacement for `npm audit` or `pip-audit`.

* FG-104 lock: an unstake/withdraw in a contract that has a stake function and a lock-period variable, with no clock read. Reentrancy flags such as `locked` are not lock periods.
* FG-110 timelock: a fee/tax/penalty setter with no upper bound, in a file with no timelock, queue, delay or pending value. It cannot see that the owner is itself a timelock contract; switch it off in that case.
* FG-117 parallel arrays: two array parameters indexed in a loop with no `a.length == b.length` check, unless both arrays are handed whole to another call (a hash or a validator).
* FG-127 to FG-129 WebSockets: `ws`, `websockets`, flask-sock and Flask-SocketIO servers. An `origin`, `verifyClient` or `allowRequest` anywhere in the file counts as an Origin check.
* FG-147 state routes: POST/PUT/PATCH/DELETE routes in a file that never mentions auth, a session, a token, `login_required`, a guard or a permission. Login, signup, reset, webhook and health paths are skipped.

* FG-151 domain separator: a state variable named like `DOMAIN_SEPARATOR` assigned from `keccak256(...)`, in a file with no `block.chainid ==` / `!=` comparison (or OpenZeppelin's and Solmate's cached-chain-id names). A literal chain id inside the encode is flagged regardless.
* FG-152 / FG-153: typehash constants are read from `keccak256("Type(...)")` in the same file; only the primary type's fields are counted. A dynamic field passed as a `bytes32` (already hashed) is fine.
* FG-155: an external, state-changing, non-admin function whose recover call takes a `bytes32` parameter (also through `toEthSignedMessageHash`). `isValidSignature` (ERC-1271) and digests compared against a recomputed hash are skipped.
* FG-157: only leaves whose two arguments are known 32-byte words. `abi.encodePacked(address, uint256)` is 52 bytes and not flagged.
* FG-163: literal values only. `2**14`, `1 << 15` and values read from config are not judged.
* FG-165: the whole file is the unit; any HMAC, tag, GCM, Poly1305, Fernet or `hash_equals` in it counts as authentication.
* FG-169: JavaScript files with server markers (`req.`, express, fastify, koa, Next.js request objects) and no `verify` call. Browser code reading its own ID token is not flagged.
* FG-72 short tokens no longer fires on an IV or nonce assignment: a 12-byte GCM nonce is the right size.

0.18 rules were checked against OpenZeppelin 5.1 and 4.9, Solady, Solmate, Uniswap v2 and v3 core and v2 periphery, crypto-js, node-forge, jsonwebtoken, jws, express, ws, socket.io, axios, Django, Flask, requests, PyJWT and cryptography. The hits were Uniswap v2's `DOMAIN_SEPARATOR` cached in the constructor (FG-151, a known property of that pair) and Django's deliberately insecure `MD5PasswordHasher` (FG-164). Library code that defines cipher modes (crypto-js `mode-ecb.js`) or curve key sizes (cryptography's `SECP521R1.key_size = 512`) is not usage and is not flagged.

0.16 rules were checked against OpenZeppelin 5.1, Solady, Synthetix, Uniswap v2/v3, express, express-session, ws, socket.io, jsonwebtoken, multer, cors, Apollo Server and GraphQL Yoga. Outside the libraries' own internals (which `node_modules` skipping already hides) the only hits were four Synthetix owner functions that index two arrays without a length check (FG-117), which is what the rule describes.

Calibrated against OpenZeppelin 5.1 (plain and upgradeable), Solady, Uniswap v2/v3, express, express-session, passport, jsonwebtoken, requests, httpx, lxml and bs4. On that corpus the rules report: four OpenZeppelin upgradeable presets with a public `initializer` and no constructor lock (FG-21, which OpenZeppelin's documentation also asks you to add), pre-0.8 Uniswap files doing unchecked math (FG-48), one example swap with a zero minimum (FG-39), the v3 payable multicall (FG-44), and an `express` 4.17.3 dev pin (FG-90). The rules read source text, not data flow, so tune them per project:

```toml
[score]
ignore = ["src/legacy/**", "frontend/vendor/*"]   # globs relative to the scanned folder
max_depth = 8                                     # folder levels below the target (0 = the target folder only)

[score.severity]
"FG-02" = "MEDIUM"        # by signature id
"WEB-RATE-LIMIT" = "off"  # or by rule name; works for every rule, signature or not
```

`foundryguard score` and the window read the nearest `foundryguard.toml` at or above the target; `--config` points at another one.

## Risk scoring

`foundryguard score`, `foundryguard bridge` and the desktop console rate a codebase from 1 to 100. The score starts at 100 and every finding deducts by severity: CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3. One rule deducts at most three times its weight, so a repeated pattern does not mask the rest of the findings. The floor is 1. The scale is strict by design: an unvalidated amount parameter, a privileged variable anyone can set, or a state write after an external call each cost 15 to 25 points.

Each deduction lists the file and line, the severity, the signature, the layer (L1 input validation, L2 access control, L3 mutability, L4 state drift, L5 external calls, L6 injection, L7 secrets, L8 transport, L9 configuration, L10 fuzzed invariant, L11 Web2 to Web3 bridge, L17 threat intel rules, L18 cryptography) and the mitigation. The report closes with a remediation plan grouped by rule.

Inputs:

- **Solidity**, for the FG-01 to FG-50 and FG-104 to FG-125 rules. Rules tied to a preset follow the preset toggles.
- **Backend and site code** (`.py`, `.js`/`.ts`, `.html`, `.php`), for the backend rules.
- **Dependency manifests** (`package.json`, `package-lock.json`, `requirements*.txt`), for FG-90.
- **A URL**: one GET of the page. Response headers and the returned HTML and inline scripts are checked. Nothing else is requested and nothing is fuzzed against the host, so only point it at sites you own or are authorised to test.

`test`, `lib`, `node_modules`, `script` and build folders are skipped, as are `*.t.sol` files.

For Solidity the report also carries a simulation matrix: one row per contract, one column per preset. ARMED means the AST detectors used by `foundryguard gen` would generate that suite; FLAGGED means a scoring rule for that preset matched. With `--fuzz` (default in the console), forge on `PATH` and a `foundry.toml` above the target, the dynamic pass runs `foundryguard run --test`; every broken invariant becomes a CRITICAL L10 deduction and the forge results are embedded in the same report.

```sh
foundryguard score .                        # score the project, write foundryguard-report.html
foundryguard score . --fuzz --min-score 75  # add the dynamic pass; exit 1 below 75 (CI gate)
foundryguard score src/Vault.sol --presets 1,4,8 --json
foundryguard score https://app.example.com  # one passive GET; report in ~/foundryguard-reports/<host>/
```

## Desktop console

`foundryguard-gui` (or `foundryguard gui`) opens the assessment console, built on customtkinter. Tk is provided by `python3-tk` on Debian and Ubuntu and is bundled with the python.org installers.

| Element | Function |
| :-- | :-- |
| Target bar | Local project path, single file, or `http(s)` URL |
| Preset grid | Eight vector toggles (Presets 01 to 08) in a 4 x 2 grid |
| LAUNCH SECURITY SIMULATION | Runs the static pass, the preset matrix and, when available, the dynamic pass |
| Progress row | Progress bar, elapsed time and Stop; the run executes on a background thread so the window stays responsive |
| Score card | Final score, coloured green, amber or red by band |
| Signature counter | Under the title: `Signatures: 170 hardcoded + N dynamic verified`. The sync runs on its own thread at start-up, so the window is usable at once |
| Log | Progress while running; at the end, every deduction ranked by severity with its signature id, file and line, points, the source line and the fix example (first 300; the report has all) |

The layout is flat and dark: charcoal background, slate cards, white text and one muted green accent. On completion the HTML report opens in the browser with the score at the top, and `foundryguard-score.json` plus `foundryguard-findings.log` (the same per-deduction listing as the window log, as plain text) are written next to it.

## Static analysis: contract model

The scan never reads Solidity text. It asks solc for the compact JSON AST and works on the nodes, so formatting, comments, overloads and imports are resolved by the compiler.

Compiler drivers (`--compiler`, default `auto`, tried in this order):

| Driver | Where it comes from |
| :-- | :-- |
| `solc` | `--solc PATH` or `$FOUNDRYGUARD_SOLC`, the Foundry (svm) and solc-select caches, `solc` on `PATH` |
| `solcjs` | `npm install -g solc` |
| `forge` | `forge build --ast --build-info` |

The solc drivers use Standard JSON with the remappings from `remappings.txt`, `foundry.toml` and `forge remappings`, and `node_modules` as an include path, so Foundry and Hardhat layouts both work. They compile twice: a parse-only pass first, so a syntax error or a missing import stops the scan at once with `file:line:col`, then the full analysis for the typed AST. Any compiler error stops the scan. The version pinned in `foundry.toml` (`solc_version`) is used first; otherwise the newest installed compiler that accepts the pragmas.

`--ast PATH` reads an AST built elsewhere (forge `out/`, a build-info file, or Standard JSON output), and `--save-ast PATH` keeps the one FoundryGuard compiled. Before the walk the tree is validated: a node that lacks a field the parser needs, a legacy (pre-compact) AST or an AST without type analysis is rejected with the node path.

From the AST the blueprint (`foundryguard.blueprint/v2`) records, per contract: the solc C3 linearization by fully qualified name (`src/Vault.sol:Vault`), so parents from OpenZeppelin, Solady or Solmate are matched by declaration, not by name, and two different `ERC20` parents stay apart; the interfaces in the lineage; where each dependency comes from; every function with its exact `stateMutability`, modifiers, overrides and selector, and every parameter with its canonical type, `typeIdentifier` and data location; and every state variable with its visibility, constant or immutable flag and, for public ones, the getter solc generates (mapping keys become parameters). The injector uses the lineage to collect inherited functions and still reads v1 blueprints.

Functions are classified by name:

| Category | Names (prefix) |
| :-- | :-- |
| deposit | `deposit`, `mint`, `supply`, `fund`, `addLiquidity`, `provide`, `topUp` |
| withdraw | `withdraw`, `redeem`, `exit`, `removeLiquidity`, `burn`, `emergencyWithdraw` |
| stake in / out | `stake`, `lock`, `bond`, `createLock` / `unstake`, `unlock`, `unbond`, `cooldown` |
| reward | `claim`, `getReward`, `harvest`, `collect`, `compound` |

Add or ignore names under `[classify]` in `foundryguard.toml`.

## Dynamic analysis: invariant suites

FoundryGuard compiles the Solidity, finds the functions that move value in the AST, and writes a `Handler.sol` and an `Invariant.t.sol` per contract. Contracts that depend on each other (a vault and its oracle, a vault and its strategy) get one suite for the whole cluster. The generated `setUp` deploys, wires and funds what it needs.

### Generated setUp

- Token constructor or initializer arguments get a mock ERC-20. Every actor is funded and approves the target.
- Reward tokens are funded through a `notifyRewardAmount`-style function when there is one.
- `initialize(...)` with an `initializer` modifier is deployed behind an ERC-1967 proxy.
- The test contract deploys the target, so it is the owner. Admin-only functions are not fuzzed.
- Withdraw amounts are bounded by `maxWithdraw`, `maxRedeem`, `balanceOf` or `stakedOf`.
- Arguments it cannot guess (structs and similar) block generation, and the report says which `[contracts.<Name>]` value to set.

Every handler call runs in `try/catch` and ghost totals change only on success, so suites work with `fail_on_revert = true`.

### Invariant presets

| Preset | Invariants |
| :-- | :-- |
| ERC-4626 | `previewsHonoured`, `depositAlwaysMintsShares`, `solvency`, `sharesBackedByAssets`, `assetsOutBoundedByIn`, `sharesOutBoundedByIn` |
| Single-unit vault | `withdrawalsBoundedByDeposits` |
| Staking / ERC-20 accounting | `actorBalancesBoundedByTotal`, `tokenSolvency` |
| Rewards | `rewardsBoundedByFunding_<token>` |
| 04 Hook read-reentrancy | `hook_readConsistency`, `hook_lockEngagedDuringCallback`, `hook_guardedFlowsNotReentered` |
| 05 Transient storage | `transient_slotsClearedBetweenCalls` |
| 06 Flash-loan price squeezing | report-only: the manipulable-price surface is flagged in the report, no invariant is generated |
| 07 Governance flash-mint | `governance_powerNotFlashInflatable` |
| 08 Economic read-reentrancy | `readReentrancy_viewsConsistentOnPayout` |
| All | `afterInvariant` fails a run in which no value-flow call succeeded |

### Preset 04: hook read-reentrancy

Applies to contracts that call an external hook in the middle of a flow: Uniswap v4 hooks (`beforeSwap`, `afterAddLiquidity`, ...), `before*`/`after*` calls on a hook, `unlockCallback`, `lockAcquired` or `*Callback` on `msg.sender`, and `onFlashLoan`.

The generated suite makes every fuzz actor a `<Contract>HookProbe` and registers one as the hook (through a hook-typed constructor or initializer argument, or a `setHook`-style setter). When the contract calls out, the probe:

- reads its price and accounting views and checks they match the state before or after the flow, not something in between (`invariant_hook_readConsistency`);
- checks that the lock getter (`locked`, `reentrancyGuardEntered`, ...) reads true (`invariant_hook_lockEngagedDuringCallback`);
- tries to re-enter the running flow if it is `nonReentrant` or `lock`, and fails if that works (`invariant_hook_guardedFlowsNotReentered`).

`tests/foundryguard/fixtures/hooks` has a broken `HookedVault`, its fixed `GuardedHookVault` and a v4-style `UnlockPool`. CI requires the first to fail and the other two to pass.

### Preset 05: transient storage

Applies to contracts that call `tstore` in inline assembly, in their own functions and modifiers or anywhere in their parents. The parser finds the calls in the Yul part of the AST and works out the slot when it is a literal, a Solidity constant, a `let` of either, or simple arithmetic on those (`add(BASE, 1)`). A slot computed at run time, such as `add(BASE, caller())`, is listed in the report with a note.

A contract cannot read another contract's transient storage, so the suite deploys `<Contract>TransientHarness`: the target plus one view that reads its own slots. The handler then:

- reads every watched slot after each successful call, while the transaction is still running;
- has a `transientSequence` action that makes two to four calls back to back in one transaction, the way a multicall or a router does.

`invariant_transient_slotsClearedBetweenCalls` fails when a slot is still set after a call has returned. If a slot is meant to live for the whole transaction, list it under `transient_ignore`. Slots the parser cannot resolve go under `transient_slots`. `transient = false` turns the preset off for a contract.

`tests/foundryguard/fixtures/transient` has `TransientStaking` and `LeakyTransientStaking`. CI requires the leaky one to fail this invariant and the fixed one to pass everything.

### Preset 06: flash-loan price squeezing

Applies to contracts that read a price, value or amount from a source an attacker can move inside one transaction: their own token or ETH balance (`token.balanceOf(address(this))`, `address(this).balance`), or a spot read on a contract they hold (`getReserves`, `slot0`, `getAmountOut`, `latestAnswer`, ...) used in a value flow. The parser records each function's self-balance reads and its internal call graph, so a priced view that reaches the balance through a helper — `convertToAssets` → `_backing` → `balanceOf(address(this))` — is caught, while a standalone `skimmable()` that reads the balance but prices nothing is not.

This preset is report-only: it names the manipulable price source and the priced views read off it in the report and the setup notes, and generates no pass/fail invariant. The obvious check — "a bare donation never moves a priced view" — is a false positive, because a donation moving a vault's share price up is normal, correct behaviour (the amount is shared among existing holders), not a bug. Whether it is exploitable turns on whether value then flows at the squeezed price within the same transaction, an economic judgement a fuzzer cannot make — so FoundryGuard surfaces the surface to squeeze (borrow, donate to push the price, transact against it, withdraw the donation, repay) and leaves the call to a human. Price off a TWAP or internal accounting that ignores unsolicited transfers.

`tests/foundryguard/fixtures/flashloan` has a spot-priced `SpotPricedVault` (its redemption price is read off the live balance) and an internally accounted `AccountedVault` (it is not). CI requires the first to be flagged and the second to be left clean, with no invariant generated for either.

### Preset 07: governance flash-mint vote hijacking

Applies to contracts with a vote entry point (`castVote`, `vote`, ...) and a per-account voting-power getter (`getVotes`, `votingPower`, or plain `balanceOf`). A vote is safe only when its weight is fixed to a snapshot taken at proposal time or a past checkpoint; when the weight is read live, an attacker flash-mints or flash-borrows the governance token, votes, and returns it in one transaction.

When the contract exposes a public mint/issue the test can flash-acquire with, the handler has a `flashVote` action: it reads an actor's voting power, grants that actor a large amount of the governance token in the same transaction, and reads the power again. `invariant_governance_powerNotFlashInflatable` fails if the power rose, because that rise is weight a flash loan would vote with and hand straight back. A checkpointed design (`getPastVotes`, an `ERC20Snapshot`, a balance recorded at proposal time) returns the same power no matter what is acquired in the current block. A governance contract with no mint the test can drive is reported, not generated.

`tests/foundryguard/fixtures/governance` has a live-weight `FlashVoteGovernor` and a checkpointed `SnapshotGovernor`. CI requires the first to fail and the second to pass.

### Preset 08: economic read-reentrancy via view functions

Applies to a value flow that pays the caller before it finishes updating accounting, so the payment hands control back (a native `receive` / `fallback`) while an economic view (`totalAssets`, `pricePerShare`, `getReserves`, `convertToAssets`, ...) reads a half-settled state a reader would act on. The parser walks the function body in source order and flags a native payment (`call{value:}`, `transfer`, `send`) that comes before a write to an accounting state variable.

The suite reuses the Preset 04 probe: every actor is a probe that snapshots the economic views when the target pays it mid-flow. `invariant_readReentrancy_viewsConsistentOnPayout` fails when a view read during the payment matches neither the pre-flow nor the post-flow state. The fix is checks-effects-interactions (settle before paying) or a read lock the views honour. A token payment before settlement (an ERC-777 `tokensReceived` risk) is reported rather than fuzzed, since reproducing it needs the ERC-1820 registry. Contracts that already call an external hook are left to Preset 04.

`tests/foundryguard/fixtures/read-reentrancy` has a pay-before-settle `NativeYieldVault` and a checks-effects-interactions `SafeNativeYieldVault`. CI requires the first to fail and the second to pass.

### Cross-contract ecosystems

Many DeFi bugs need two contracts to get out of step: a vault that is fine until its oracle moves, a strategy that reports assets the vault already paid out. A suite that deploys one contract with a placeholder address for everything else cannot reach them. So the scan also maps how your contracts point at each other, and the generator deploys linked contracts together.

What the parser records, per contract, from the AST (`links` in the blueprint):

- every state variable whose type is a contract or interface (`IPriceOracle public oracle`, `IERC20 immutable asset`), and every `address` variable the code casts to one (`IPriceOracle(oracle).price()`);
- where it is set: a constructor or initializer parameter, a setter such as `setStrategy(address)`, or `new X()` in the constructor. A link set through an internal helper falls back to the constructor parameter of the same type;
- which external functions are called on it, and from which functions.

Each link is then resolved (`ecosystem.edges`). A concrete project contract resolves to itself. An interface or abstract type resolves to the project contract that has it in its C3 lineage, matched by declaration, not by name. Token types get a mock ERC-20, as before. Hook types are left to Preset 04. When several contracts implement the interface, the first one is used and the report says so; choose with `[ecosystem.bind]`.

Linked contracts form clusters (`ecosystem.clusters`). Each cluster has a deploy order (a contract comes after everything its constructor or initializer needs), its root contracts, any constructor cycle, and a dependency matrix:

```text
                  0 1 2
PriceFeed         . . .   0
LeakyOracleVault  x . .   1
OracleVault       x . .   2
```

A row depends on a column. The generator writes one suite per cluster to `test/foundryguard/<Name>Ecosystem/`:

- `setUp` deploys every member in order and passes each one the addresses of the members it needs. Members created with `new` are read back through their getter. Links set through a setter are wired after deployment. Token mocks are shared when the parameter names match, so a vault and its strategy hold the same asset.
- One master handler drives the whole cluster: value flows on every member, other unrestricted state-changing calls, and admin-only calls on the members others depend on (price pushes, rate updates), made as the admin. Calls that change ownership, upgrade code or rewire a link are not fuzzed. `ecosystemSequence` runs two to four of these calls across members in one transaction.
- Invariants hold across the cluster: `ecosystem_wiringIntact` (every public link still points at what `setUp` wired), `ecosystem_<Member>_tokenSolvency`, `ecosystem_<Member>_<unit>OutBoundedByIn`, `ecosystem_<Member>_actorBalancesBoundedByTotal`, `ecosystem_tokenConservation_<token>` (no token leaves the actors, members, handler and test), and `afterInvariant`.

A contract whose constructor or initializer needs another member gets only the ecosystem suite, since on its own it would run against a placeholder. Members that stand alone keep their standalone suites and presets.

`tests/foundryguard/fixtures/ecosystem` has a `PriceFeed` read by two vaults. `OracleVault` books deposits in tokens. `LeakyOracleVault` books them as value at the current price and pays back in tokens, so after a price drop it owes more than it holds. Deployed alone, neither vault shows a problem. CI requires the ecosystem suite to fail `invariant_ecosystem_LeakyOracleVault_tokenSolvency` and nothing else, and to pass once the leaky vault is excluded.

`[ecosystem] enabled = false` or `gen --no-ecosystem` turns this off. `[targets] exclude` removes a contract from its cluster.

### AI fallback for custom contracts

The presets only fire when the AST proves they apply. A contract with its own logic (an auction, a bonding curve, a vesting schedule) gets no suite and shows up as "no drivable deposit/withdraw/stake_lock functions". With `--ai`, those contracts go to `ai_generator.py` instead. It sends the contract's lineage, constructor, public and external function signatures, state variables and its source with comments stripped to a language model, and asks for a handler with bounded inputs and ghost variables plus invariants for that contract.

Set one key and pass `--ai`:

```sh
export ANTHROPIC_API_KEY=...      # or OPENAI_API_KEY=...
foundryguard run --ai --test
```

| Variable | Use |
| :-- | :-- |
| `ANTHROPIC_API_KEY` | Anthropic Messages API. Used when both keys are set. |
| `OPENAI_API_KEY` | OpenAI Chat Completions, or any compatible server |
| `FOUNDRYGUARD_AI_PROVIDER` | `anthropic` or `openai`, to choose when both keys are set |
| `FOUNDRYGUARD_AI_MODEL` | model name (defaults: `claude-sonnet-5-5`, `gpt-4.1`) |
| `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` | proxy, Azure or local endpoint, e.g. `http://localhost:11434/v1` (a local server still needs some `OPENAI_API_KEY` value) |

`[ai]` in `foundryguard.toml` takes `enabled = true` (same as `--ai`), `provider`, `model`, `base_url`, `timeout`, `max_tokens` and `max_source_chars` (default 12000). Keys are only read from the environment. In CI, pass the key as a secret.

What it does and does not do:

- Nothing is sent without `--ai` or `enabled = true`, even if a key is set. Contracts a preset handles never reach the model. Your source does leave the machine, so check that this is allowed for the code you scan.
- The answer is checked before it is written: both `<Contract>AIHandler` and `<Contract>AIInvariantTest` must be there, the handler must import the target, the test must have an `invariant_*` function, and `vm.ffi`, file, environment, RPC and broadcast cheatcodes and console logging are refused. A refused answer writes nothing and the reason is in the report.
- Generated files start with `// @generated by FoundryGuard AI` and the model name. They are not regenerated unless you pass `--force`, so each run does not cost an API call, and `check` and `--dry-run` never call the model.
- Model output is a draft. It may not compile, and an invariant may be wrong in either direction. Read every invariant before you trust a green run.

### Self-healing build

The templates target a recent solc 0.8, but the project decides which compiler actually runs. A repo pinned to 0.8.19, a newer solc that is stricter about a specifier, or a model-written AI suite can leave a generated file that does not build. So after `gen` and `run` write the suites, FoundryGuard compiles them and repairs what it can:

1. compile every file under `test/foundryguard/` that carries the `@generated by FoundryGuard` marker, with `forge build --json` when forge is on PATH, otherwise solc or solcjs through Standard JSON;
2. match each diagnostic that points into a generated file against a fixed set of rules and turn it into a small edit at the reported location;
3. write the edits and compile again, until there are no errors, no rule applies, or five rounds have passed.

| Diagnostic | Fix |
| :-- | :-- |
| pragma the installed solc does not satisfy | pragma set to `^<installed version>` |
| missing, invalid or disallowed data location | `memory` (or the allowed location) added, replaced or removed |
| no visibility specified | the visibility solc suggests is added after the parameter list |
| visibility, mutability or override given twice, or not allowed (free functions, interfaces) | the extra specifier is removed or replaced |
| missing `override`, `override(A, B)` or `virtual`; `override` on a function that overrides nothing | specifier added or removed |
| `view`/`pure` on a function that writes or reads state | relaxed to `view` or removed |
| warning: mutability can be restricted, unused parameter, no SPDX line | `view`/`pure` added, name commented out, `MIT` header added |

Each fix is printed as `healed <file>:<line> [rule] old -> new`. Only generated files are edited. An error in your own sources is listed and the command exits 1, and so does a generated file that still fails after the last round. If an import does not resolve (no `forge-std` installed yet, say), the check is skipped with a note instead.

Fixes are kept in `test/foundryguard/foundryguard.heal.json` as old and new lines. The next `gen --force` applies them to the fresh render, so a healed suite stays healed and `check` does not report it as stale. Commit the file with the suites.

The loop is on by default when forge is on PATH. `--heal` turns it on with solc or solcjs, `--no-heal` turns it off, `--heal-compiler` and `--heal-rounds` pick the driver and the limit. `foundryguard heal` runs it alone, for example after editing a suite by hand. In `foundryguard.toml`:

```toml
[heal]
enabled = true
compiler = "auto"    # forge, solc or solcjs
max_rounds = 5
warnings = true      # set to false to fix errors only
```

The rules are deliberately narrow. Anything else (a wrong type, a missing function, an invariant that does not make sense) is reported as it is and left for you to fix.

### Forge run report

`foundryguard report` and `foundryguard run --test` write `FoundryGuard_Report.md` to the project root (`--report PATH` to move it, `--no-report` to skip it). It reads forge JSON or stdout and shows PASSED/FAILED per test and, for each broken invariant, the shrunk call sequence, a Solidity replay test and the command to rerun it. Forge 1.x does not print the sequence for invariant campaigns, so the report reads it from `cache/invariant/failures/`.

The same results also go to `foundryguard-report.html` next to the Markdown file (`--html PATH` to move it, `--no-html` to skip it). It is one static page with no scripts or external files: run metrics, a table per suite, and each failed execution path as a collapsible tree of calls with sender, target, named parameters and, when the trace has them (`-vvvvv`), the storage slots each call changed. The last node is the invariant check with both sides of the failed assertion and their difference.

The metrics count each invariant campaign once. Forge 1.x runs all invariants of a test contract in one campaign and prints its stats on every one of them, so adding them up per test would multiply the calls. Fuzz inputs are invariant handler calls plus fuzz runs. Execution time is forge's own wall clock from stdout; JSON output has no wall clock, so the report shows the sum of suite durations and says so.

```sh
forge test -vvv | foundryguard report -
```

## Backend-to-contract bridge validation

Signature mints, claims, relayers and bridges usually break at the seam: a route that signs whatever the request asks for, a nonce the backend puts in the payload and the contract never consumes, an EIP-712 struct that drifted from the contract's typehash. `foundryguard bridge` (and every `foundryguard score` run) reads both sides of the repository together and checks that seam. Point it at a repo that holds the contracts and the Node or Python backend.

Each place a server key signs (EIP-712 typed data or a raw message) is linked to the contract function that verifies it, by EIP-712 primary type or by the function the backend calls. The pair is then judged as one:

| Rule | What it means |
| --- | --- |
| `BRIDGE-SIGNING-ORACLE` | a route signs with the server key and never checks who is calling |
| `BRIDGE-OPEN-RELAYER` | a route sends transactions from the server key for any caller |
| `BRIDGE-SIGNED-INPUT-UNCHECKED` | the caller is checked, but the signed values from the request are not bounded |
| `BRIDGE-TYPEHASH-DRIFT` | the backend's EIP-712 struct differs from the contract's typehash (names, types or order) |
| `BRIDGE-DOMAIN-DRIFT` | domain name, version or fields differ between backend and contract |
| `BRIDGE-SIG-REPLAY` | the verifier never marks the nonce or digest used |
| `BRIDGE-DEADLINE-UNENFORCED` | the backend signs an expiry the contract never checks |
| `BRIDGE-SIG-NO-DOMAIN` / `BRIDGE-SIG-UNBOUND` | the signed digest is not bound to the chain id and contract address |
| `BRIDGE-ABI-DRIFT` | the backend calls a function or argument count the contracts in the repo do not expose |
| `BRIDGE-KEY-*`, `BRIDGE-MNEMONIC-LITERAL` | key read from a request, logged, shipped to the browser through a public env var, or a seed phrase in source |
| `BRIDGE-TX-NONCE-RACE`, `BRIDGE-WEAK-NONCE` | transaction nonces set by hand without a lock; signature nonces from a clock or an in-memory counter |
| `BRIDGE-RECEIPT-STATUS`, `BRIDGE-REORG` | a receipt trusted without checking `status`; events acted on with no confirmation depth |

Findings count toward the score under L11 and the HTML report gets a bridge map: one row per signing site with its route, whether the caller is authenticated, the verifier, and whether chain, contract, nonce and expiry are actually enforced.

```sh
foundryguard bridge .                  # bridge map + findings, exit 1 on HIGH or worse
foundryguard bridge . --fail-on CRITICAL --json
```

Express, Fastify-style routers, Next.js route handlers, Flask and FastAPI routes are recognised. ethers, viem, web3.js, web3.py and eth-account cover the signing and sending side. Nothing is executed and nothing is sent anywhere.

## Threat intel sync

Layer 17 (`intel_sync.py`) adds detection data from public feeds without touching the built-in database. The 170 signatures stay as shipped; the extra rules and advisories live in memory and in a cache file (`~/.cache/foundryguard/intel.json`).

| Feed | What it gives |
| :-- | :-- |
| [OSV](https://osv.dev) (`api.osv.dev`) | Vulnerable version ranges for the watched npm and PyPI packages (the built-in list plus `[intel] packages`). FG-90 then reports any pinned version inside a range, with the CVE or GHSA id |
| Rule packs | JSON line rules tied to an SWC, CWE or CVE id. The default pack is [`intel/foundryguard-rules.json`](intel/foundryguard-rules.json) in this repo: SWC-129 (`=+` typo), SWC-130 / CVE-2021-42574 (bidi characters), SWC-111 (deprecated built-ins), SWC-136 (secrets in `private` state) and CVE-2007-4559 (`tarfile.extractall` without a filter) |

What counts as verified: a feed must be https on an allowed host and under 2 MB, and can be pinned to a SHA-256. Each rule needs an `FGX-` id, a known severity, an SWC/CWE/CVE/GHSA reference and a pattern under 300 characters with no backreferences or nested repeats, and it must match its own `test.hit` line and not its `test.miss` line. Advisories need an id, a package and a numeric range. Anything that fails is dropped on its own; the cache is checked the same way when it is read back. Fetched data is parsed as JSON and compiled as a regex, nothing else.

Order of fallback: network, then the last good cache, then the built-in 170 alone. A cache younger than `max_age_hours` is used without going to the network. Dynamic hits appear in the report under "Dynamic signatures" with layer L17 and can be tuned by id like any other rule (`"FGX-SWC-129" = "off"`).

```toml
[intel]
auto_update_signatures = true     # the window syncs at start-up; `foundryguard score` reads the cache
# max_age_hours = 24
# osv = true
# packages = { npm = ["next"], pypi = ["django"] }
# feeds = ["https://example.org/rules.json"]   # extra packs; their hosts become allowed
# [intel.pins]
# "https://example.org/rules.json" = "<sha256>"
```

Without a `foundryguard.toml` the window syncs by default and the command line does not. `foundryguard intel sync` fetches on demand.

## Reporting

| Output | Produced by | Contents |
| :-- | :-- | :-- |
| `foundryguard-report.html` | `score`, `bridge`, console, `run --test` | Score, findings by signature with fix examples, bridge map, simulation matrix, forge results, full signature catalogue |
| `foundryguard-score.json` | `score`, console | The same data for scripts |
| `FoundryGuard_Report.md` | `run --test`, `report` | Pass/fail per test, shrunk call sequences, replay tests, rerun commands |
| `foundryguard.sarif` | `report`, GitHub Action | Code-scanning alerts on the failing `invariant_*` function |

## Configuration

```toml
[classify]
deposit = ["enter", "join"]
ignore = ["mintFee"]

[contracts.MyVault]
constructor_args = ["address(asset)", "\"Vault\"", "\"vTKN\""]
setup = ["vm.warp(1 days);"]
transient_slots = ["0x..."]     # Preset 05: extra slots to watch
transient_ignore = ["0x..."]    # Preset 05: slots that may stay set for the whole transaction

[ecosystem]
setup = ["vm.warp(1 days);"]    # extra setUp lines for every ecosystem suite

[ecosystem.bind]
IPriceOracle = "ChainlinkAdapter"   # which contract fills a link, by interface
"MyVault.oracle" = "TwapOracle"     # or by contract.variable; "mock" forces a mock token
```

`constructor_args` under `[contracts.<Name>]` also apply when that contract is deployed inside an ecosystem.

Settings live in the config, so regenerating with `--force` keeps them.

## CI integration

```yaml
- uses: foundry-rs/foundry-toolchain@v1
- uses: Rey-LLM/foundry-invariant-vault-patterns@main
  with:
    args: --contract MyVault
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: foundryguard.sarif
```

Broken invariants show up as code-scanning alerts on the failing `invariant_*` function. This repo's own workflow runs the Python tests on 3.9 and 3.13 with solc 0.8.24, fuzzes the fixture projects with forge (including the ecosystem one), maps this repo's modules and runs module 05, and resolves OpenZeppelin and Solady parents through both the solc and forge drivers, and breaks a generated handler on purpose to check that `foundryguard heal` gets it building again with forge. Run the tests locally with `python3 -m unittest discover -s tests/foundryguard -v`. Tests that compile are skipped when no solc or solcjs is installed; the OpenZeppelin/Solady ones also need `npm install` in `tests/foundryguard/fixtures/libs`.

## Reference invariant suites

The repository also carries hand-written invariant suites for DeFi failure classes that FoundryGuard's presets are derived from. The contracts under `src/` are test targets, and several are vulnerable on purpose so the invariants have something to catch. They are not for deployment.

| Module | Contract | What the invariants check |
| :-- | :-- | :-- |
| 01 ERC-4626 share inflation, `src/erc4626-inflation/` | `MockERC4626.sol`, a vault without virtual reserves | asset and share conservation, a positive deposit mints shares, withdrawals burn enough shares, results match previews |
| 02 TWAP oracle, `src/twap-validation/` | `PriceOracleModel.sol`, a cumulative-price TWAP with bounds and a 10% per-update cap | spot within bounds, cumulative matches ghost accounting, TWAP within the observed range, bounded short-window drift |
| 03 Staking rewards, `src/flashloan-reward/` | `StakingPool.sol`, a reward-per-token pool | rewards never exceed the schedule, no reward from same-block stake/unstake, `totalStaked` equals the sum of balances |
| 05 Transient storage, `src/transient-vault/` | `TransientStaking.sol`, daily staking points with a transient lock and entry bonus, and `LeakyTransientStaking`, which never clears the entry slot | every transient slot is zero again after each call and between the steps of a multicall, stake and point totals match the sum of balances, token solvency |

Each module has a reference contract, a handler that makes bounded valid calls and keeps ghost accounting, and an invariant test that compares the contract's state with that accounting. Two suites in module 01 fail on purpose to show the defects. `ProtectedInvariant` shows the fix.

Module 05 is about a mistake that is easy to make with `TSTORE`: EIP-1153 clears transient storage when the transaction ends, not when the call returns. So a test that looks at the slots after the transaction always passes. The bug shows up inside the transaction, when the next call (a multicall step, a router hop, a callback) reads a value the previous call left behind. The handler therefore runs several calls in one transaction and reads the slots after each of them. `LeakyTransientStakingTest` shows the effect: in `multicall([stake, claimPoints, claimPoints])` the leaky version pays the entry bonus three times.

```sh
forge install foundry-rs/forge-std --no-git
forge install OpenZeppelin/openzeppelin-contracts --no-git   # module 01 only
forge test -vvv
```

Run one module with `--match-path`, for example `forge test --match-path "test/twap-validation/*"`. A failing invariant prints the call sequence that broke it; rerun with `-vvvv` for the full trace. For a deeper CI run, set `runs = 256`, `depth = 128` under `[profile.ci.invariant]` and run with `FOUNDRY_PROFILE=ci`.

To reuse a pattern, copy the closest handler and test, point the handler at your contract, and keep the ghost accounting independent of the contract's own math.

## Verification

```sh
python3 -m unittest discover -s tests/foundryguard -v
```

The suite holds 505 tests covering every layer, with weak and safe fixture pairs for the signatures, presets and bridge rules. Tests that compile Solidity are skipped without solc or solcjs (`npm install -g solc`); the OpenZeppelin and Solady resolution tests also need `npm install` in `tests/foundryguard/fixtures/libs`; the desktop console tests are skipped without a display. CI additionally fuzzes each fixture project with forge and requires every weak fixture to fail and every safe fixture to pass.

### Engine performance

The scan reads each file once with a bounded read (no separate stat), walks folders with `os.scandir`, strips comments with one compiled tokenizer instead of a per-character loop, and gives every line rule a set of literal hints so a rule only runs line by line on files that contain one of them. Every fixed regex in the bridge validator and the AST parser is compiled once at import; per-identifier patterns and function-name classification are cached. On a 2,674-file JavaScript corpus the line-rule pass went from 41 s to 29 s with identical findings, and the folder walk and file reads take about half the time they did. A test checks that every line a rule matches contains one of its hints.

0.18 profiled the scan on Django, Flask, requests, PyJWT, cryptography, express, crypto-js, OpenZeppelin, Solady and Uniswap and removed the hot spots it found:

* Line rules only hand the regex the lines that contain one of the rule's hints. The lines are found with `str.find` on the lowercased file and mapped back with a binary search, so most lines of a file never reach the regex engine.
* File-level `needs` / `unless` patterns run only after a line has matched, and each runs at most once per file. Before, they scanned every file in full for every rule, which was half the total time on Python code.
* The project-wide limiter, security-header and Web3 checks skip the regex when none of their literals is in the file (Python's `re` has no literal prefilter for case-insensitive alternations).
* File-level backend checks run the narrow pattern first (an auth route, an HTTP client call, a `jwt.sign`) and the whole-file pattern only when it hit.
* Inside one scan, each `.sol` file is stripped and parsed once and shared between the contract rules, the diamond-slot pass and the bridge validator.

| Corpus | Files | 0.17 | 0.18 |
| :-- | --: | --: | --: |
| Python (Django, Flask, requests, PyJWT, cryptography) | 1,207 | 22.5 s | 5.8 s |
| JavaScript (express, ws, socket.io, crypto-js, node-forge, axios) | 72 | 2.0 s | 0.6 s |
| Solidity (OpenZeppelin, Solady, Uniswap v3) | 319 | 4.3 s | 3.8 s |

The 0.18 times include the 20 new signatures. Findings from the 0.17 rules are identical on all three corpora, and `test_layer18` compares the line-rule engine against the plain one-line-at-a-time version on every fixture.

## Scope and known limitations

- The suites are a starting point, not an audit. Add the protocol-specific invariants only you can state.
- Functions with array, struct, `bytes` or `string` parameters are skipped. That includes a real v4 `PoolManager`.
- Non-token contract arguments (oracles, routers) are wired to a project contract that implements them. When none does, they get `address(this)` with a note. Pass real mocks through `constructor_args`.
- Ecosystem suites only follow links stored in the contract's own state variables. An address passed per call, read from a registry, or cast in a child contract from a parent's `address` variable is not linked. Contracts whose constructors need each other are reported as a cycle and not generated.
- Ecosystem suites do not run the single-contract presets (ERC-4626 previews, hooks, transient storage) on their members.
- Presets assume no external yield. Relax `solvency` and the `*OutBoundedByIn` invariants for vaults that earn yield.
- AI suites go through the heal loop like the others, but it only fixes the specifier and pragma problems listed above. A model mistake in logic or types still needs a hand fix.
- The score's Solidity and web rules work on source text, not on data flow. They can miss a check done in another contract or flag one done in a way they do not recognise; the line in each deduction lets you judge it quickly.
- The bridge pass links signer and verifier inside one repository. A backend that signs for a contract kept in another repo is checked on its own side only, and handlers wired through a framework it does not recognise are judged as plain functions (no route, no oracle check).
- Preset 05 sees `tstore` in the contract's own lineage only. Transient storage written through a library (OpenZeppelin `TransientSlot`, `ReentrancyGuardTransient`) or Solidity `transient` state variables is not detected yet; list those slots under `transient_slots`.
- Remote targets get one passive GET. Active injection testing against a running application is out of scope; use a dedicated DAST tool such as OWASP ZAP against your own staging environment and trace its hits back to code with the file and line findings here.
- The 0.16 staking, NFT and API rules are pattern based like the rest: a lock check, ownership check or auth middleware done in another contract or file is invisible to them. Each deduction carries the line so a false hit is quick to dismiss or switch off in `foundryguard.toml`.
- The intel sync only watches named packages; it does not send your manifests anywhere. Add the packages you care about under `[intel] packages`. OSV ranges marked `last_affected` (no fixed release, inclusive bound) are skipped.
- The cryptography rules (FG-151 to FG-170) read call sites, not values that flow between functions: a key, IV or iteration count built in one place and used in another, a KMS-backed key, or an algorithm chosen from config is not judged. Java, Go and Rust code is not scanned.
- There is no dedicated detector for personal data (PII) or email addresses in source or responses. Secret and key exposure is covered by FG-51 and FG-94 to FG-96.

## License

MIT.
