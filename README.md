# 🛡️ Foundry Invariant Vault Patterns

**A QA & Security Reference Suite for Web3 Core Developers**

Stateful, invariant-driven test blueprints for the parts of DeFi that break most often: share math, price oracles, and reward accounting.

![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636?logo=solidity)
![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🎯 Mission

This repository is a **development aid and educational blueprint**. It helps DeFi protocol developers design:

- 🧮 **Stable fixed-point math** for share-based vaults
- 📈 **Solid oracle feeds** that resist short-window manipulation
- 🔒 **Secure staking mechanisms** whose rewards depend on time, not on capital that appears for one block

Each module pairs a minimal reference contract with a fuzz **handler** that drives it through valid state transitions, and an **invariant test** that checks economic properties against independent ghost accounting.

> ⚠️ **Not for production.** The contracts here are models and test fixtures. Some are deliberately vulnerable so the invariants have something to catch. Never deploy them with real funds.

---

## 🧭 Architecture Matrix

| Module | Reference contract | Handler | Invariant test | Properties protected |
| :-- | :-- | :-- | :-- | :-- |
| **01 · ERC-4626 Vault Share Inflation Math Validation**<br>`src/erc4626-inflation/` | `MockERC4626.sol`: vulnerable vault with no virtual reserves, a floor-withdraw mutation, and a mintable mock asset | `Handler.sol`: four actors doing deposit, withdraw, and direct donation | `InflationInvariant.t.sol`: stateful properties, regression matrix, and a protected control vault | Asset and share conservation · a positive deposit always mints shares · withdrawals burn enough shares · transitions match previews |
| **02 · Uniswap V3-style TWAP Oracle Price Stability Framework**<br>`src/twap-validation/` | `PriceOracleModel.sol`: cumulative-price TWAP with hard price bounds and a 10% per-update deviation cap | `OracleHandler.sol`: bounded price moves and forward time warps | `OracleInvariant.t.sol` | Spot stays within bounds · cumulative matches ghost accounting · TWAP stays inside the observed price range · short-window drift is bounded · observations are strictly monotonic |
| **03 · Multi-Token Staking & Flash-Loan Reward Validation Framework**<br>`src/flashloan-reward/` | `StakingPool.sol`: time-weighted reward-per-token staking pool | `RewardHandler.sol`: stake, unstake, claim, time warps, and same-block flash-sized stake/unstake cycles | `RewardInvariant.t.sol` | Distributed rewards never exceed the schedule · rewards match the schedule up to bounded rounding dust · zero reward from same-block cycles · `rewardPerToken` frozen within a block · `totalStaked` equals the sum of balances |

> 📌 **Module status.** All three modules are on `main`, together with the shared `foundry.toml`. Module 01 keeps its handler in `src/`, and two of its invariant suites are **expected to fail**: they demonstrate the inflation and rounding defects, while `ProtectedInvariant` shows the fix.

### 📂 Layout

```text
src/
├── erc4626-inflation/     Module 01 · MockERC4626.sol · Handler.sol
├── twap-validation/       Module 02 · PriceOracleModel.sol
├── flashloan-reward/      Module 03 · StakingPool.sol
└── cli/                   FoundryGuard · foundryguard.py · parser.py · ast_backend.py · injector.py · reporter.py · reporting.py
    └── blueprints/        invariant preset library · hook_reentrancy.py (Preset 04)
test/
├── erc4626-inflation/     InflationInvariant.t.sol
├── twap-validation/       OracleHandler.sol · OracleInvariant.t.sol
└── flashloan-reward/      RewardHandler.sol · RewardInvariant.t.sol
tests/foundryguard/        FoundryGuard unit tests + fixture project
```

### 🧩 How each module is built

1. **Reference contract.** The smallest model that shows the mechanism under test.
2. **Handler.** Calls only valid actions with bounded inputs, so the fuzzer explores real state instead of reverting, and keeps ghost variables that record what *should* be true.
3. **Invariant test.** Wires the handler with `targetContract` / `targetSelector` and asserts that the contract's state agrees with the ghost accounting after every call sequence.

---

## 🚀 Quick Start / QA Integration Guide

### 1. Prerequisites

Install Foundry from the [official installation guide](https://getfoundry.sh/introduction/installation/).

### 2. Clone and install dependencies

```sh
git clone https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git
cd foundry-invariant-vault-patterns

forge install foundry-rs/forge-std --no-git
# Needed for Module 01 only:
forge install OpenZeppelin/openzeppelin-contracts --no-git

forge build
```

Dependencies are installed into `lib/` and are not committed. The shared `foundry.toml` pins solc 0.8.24 and sets the `forge-std` and OpenZeppelin remappings.

### 3. Run a module

```sh
# Module 02: TWAP oracle stability
forge test --match-path "test/twap-validation/*" -vvv

# Module 03: staking & flash-loan reward accounting
forge test --match-path "test/flashloan-reward/*" -vvv

# Module 01: ERC-4626 inflation matrix
forge test --match-path "test/erc4626-inflation/*" -vvv

# Everything
forge test -vvv
```

### 4. Read the results

- ✅ A passing `invariant_*` line means the property held across every fuzzed call sequence.
- ❌ A failing invariant prints the **shrunk call sequence** that broke it. Re-run with `-vvvv` to see the full trace.
- 📊 Add `--show-metrics` (or set `show_metrics = true` under `[invariant]`) to see how often each handler action was called.

### 5. Tune the fuzzing depth

Add to `foundry.toml` for a harder run in CI:

```toml
[profile.ci.invariant]
runs = 256
depth = 128
fail_on_revert = true
```

```sh
FOUNDRY_PROFILE=ci forge test
```

### 6. Use a pattern in your own protocol

1. Copy the handler and invariant test for the module closest to your design.
2. Point the handler at your contract and keep its input bounds realistic.
3. Keep the ghost accounting independent of your contract's own math, because that independence is what makes the invariant meaningful.
4. Run it in CI on every change to accounting or pricing code.

---

## 🤖 FoundryGuard: Automated Invariant Scaffolding CLI

FoundryGuard turns a Foundry project into a fuzzing target with one command. It reads your Solidity, finds the functions that move value, and writes a `Handler.sol` and an `Invariant.t.sol` for each contract. The output follows the handler and ghost-accounting pattern of the modules above. The generated `setUp` deploys and funds everything it needs, so the suite runs without hand edits in the common cases.

It needs Python 3.9+ and nothing else (Python 3.9 and 3.10 also need `tomli` to read `foundryguard.toml`; `pip install .` installs it).

### Quick start

```sh
# Option A: install the command
pipx install git+https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git
foundryguard run --test          # scan + generate + forge test on the generated suites

# Option B: run from a clone, no install
python3 path/to/src/cli/foundryguard.py run
forge test --match-path "test/foundryguard/*" -vvv
```

| Command | What it does |
| :-- | :-- |
| `foundryguard init` | Writes a commented `foundryguard.toml`. |
| `foundryguard scan` | Turns Solidity into a `foundryguard.json` blueprint. |
| `foundryguard gen` | Turns the blueprint into `test/foundryguard/<Contract>/` suites. |
| `foundryguard run [--test]` | Runs `scan` and `gen`, plus `forge test` and `FoundryGuard_Report.md` with `--test`. |
| `foundryguard check` | For CI: exits 1 when generated suites are missing or stale. Writes nothing. |
| `foundryguard report results` | Turns `forge test --json` or `forge test -vvv` output (a file, or `-` for stdin) into `FoundryGuard_Report.md`, plus CI Markdown and SARIF. |

The old entry points still work: `python3 src/cli/parser.py` and `python3 src/cli/injector.py foundryguard.json`.

```text
src/**/*.sol ──▶ scan ──▶ foundryguard.json ──▶ gen ──▶ test/foundryguard/
                 (AST or regex)  (blueprint)              FoundryGuardSupport.sol
                                                          <Contract>/Handler.sol · Invariant.t.sol
```

### Scanning: AST first, regex as fallback

- `--backend auto` (the default) runs `forge build --ast` when `forge` is installed and reads the exact solc AST. It also reads existing Foundry artifacts, Foundry or Hardhat `build-info` files, and raw `solc --standard-json` output (`--build-dir <dir or file>`, `--no-build`).
- Without a compiler it falls back to the built-in regex parser. That parser strips comments, follows imports through `foundry.toml` and `remappings.txt` remappings, and resolves inherited functions. `--backend ast` or `--backend regex` forces one backend.
- Library contracts (`lib/`, `node_modules/`) are only used to resolve inheritance; they are never targets. Files that import `forge-std` are skipped as test helpers.
- If a parent contract cannot be found (for example OpenZeppelin is not installed), FoundryGuard **warns** instead of silently dropping the inherited `deposit` and `withdraw`.
- Public and external state-changing functions are classified by name:

| Category | Direction | Matches (prefix, case-insensitive) |
| :-- | :-- | :-- |
| `deposit` | in | `deposit`, `mint`, `supply`, `fund`, `addLiquidity`, `provide`, `topUp` |
| `withdraw` | out | `withdraw`, `redeem`, `exit`, `removeLiquidity`, `burn`, `emergencyWithdraw` |
| `stake_lock` | in | `stake`, `lock`, `bond`, `createLock`, `increaseLock`, `extendLock`, ... |
| `stake_lock` | out | `unstake`, `unlock`, `unbond`, `withdrawStake`, `cooldown`, ... |
| `stake_lock` | reward | `claim`, `getReward`, `harvest`, `collect`, `compound` |

Add your own names (`enter`, `join`, `leave`, ...) or ignore some in `[classify]` in `foundryguard.toml`.

### What `setUp` does for you

| Situation | Generated behaviour |
| :-- | :-- |
| A constructor or initializer takes a token (`IERC20 asset_`, `address stakingToken`, ...) | Deploys a `FoundryGuardMockERC20` for it. Every actor gets a balance and approves the target. |
| A reward token plus a `notifyRewardAmount`-style function | Funds the reward budget as the owner, whether the function pulls the tokens or expects them up front. |
| `initialize(...)` with an `initializer` modifier | Deploys the implementation behind an ERC-1967 proxy and initializes it, like in production. |
| `Ownable` / `onlyOwner` / `onlyRole` | The test contract deploys the target, so it is the owner. Admin-only functions are not fuzzed from actors. |
| Owner/receiver parameters (`withdraw(assets, receiver, owner)`) | `owner`/`from`/`account` is the pranked actor; receivers are other actors, so value stays observable. |
| Withdrawals and unstakes | Amounts are bounded by `maxWithdraw`, `maxRedeem`, `balanceOf` or `stakedOf` of the actor, so calls rarely revert. |
| A plain ERC-20 with a faucet `mint` | Not treated as a vault. Add it to `[targets] include` to fuzz it anyway. |
| A struct or other argument it cannot guess | The suite is not generated, and the report tells you which `[contracts.<Name>]` value to set. It never writes code that does not compile. |

Every handler call runs in `try/catch`. Ghost totals move only on success, and reverts are counted per action, so suites work with `fail_on_revert = true`.

### Invariant presets

Each preset is emitted only when the scanned contract supports it:

| Preset | Invariants |
| :-- | :-- |
| ERC-4626 | `previewsHonoured` (deposit/mint/withdraw/redeem never worse than `preview*`), `depositAlwaysMintsShares` (catches share inflation), `solvency`, `sharesBackedByAssets`, `assetsOutBoundedByIn`, `sharesOutBoundedByIn` |
| Single-unit vault | `withdrawalsBoundedByDeposits` |
| Staking / ERC-20 accounting | `actorBalancesBoundedByTotal`, `tokenSolvency` (token balance ≥ `totalStaked` / `totalDeposits`) |
| Rewards | `rewardsBoundedByFunding_<token>`: actors never receive more rewards than were funded |
| 04 · Hook read-reentrancy | `hook_readConsistency`, `hook_lockEngagedDuringCallback`, `hook_guardedFlowsNotReentered` (see below) |
| Always | `afterInvariant`: fails a run in which no value-flow call succeeded |

### Preset 04: hook-based read-reentrancy (Uniswap v4 style)

The scanner reads function bodies and flags a contract that calls out to an external hook mid-flow: the v4 `IHooks` surface (`beforeSwap`, `afterAddLiquidity`, ...), `before*`/`after*` calls on a hook-typed receiver, `unlockCallback` / `lockAcquired` / `*Callback` on `msg.sender`, and `onFlashLoan`. For such a contract the generated suite:

- deploys `<Contract>HookProbe` contracts and uses them as **every fuzz actor**; `hookProbes[0]` is also the registered hook, through a hook-typed constructor or initializer parameter (`IHooks hooks_`) or a `setHook(s)`-style setter;
- while a handler flow runs, each callback that reaches a probe snapshots the target's price and accounting views (`totalAssets`, `totalSupply`, `*Price*`, `*Rate`, reserves, `convertToAssets(1e18)`, ...), reads the lock getter (`locked`, `reentrancyGuardEntered`, ...), and re-enters the running flow when it carries `nonReentrant` / `lock`;
- answers every hook with its own selector followed by zero words (so `bytes4` and v4 `(bytes4, delta, fee)` returns decode), and `bytes`-returning callbacks such as `unlockCallback` with empty bytes.

| Invariant | Fails when |
| :-- | :-- |
| `invariant_hook_readConsistency` | a view read inside a callback equals neither the state before nor the state after the flow (assets sent but shares not yet burned, and so on). Views that revert mid-callback count as a read guard, not a failure. |
| `invariant_hook_lockEngagedDuringCallback` | the lock getter reads `false` while the contract is calling out |
| `invariant_hook_guardedFlowsNotReentered` | a `nonReentrant` flow was re-entered successfully from the callback |

`tests/foundryguard/fixtures/hooks` holds a broken `HookedVault` (hook runs before the shares are burned), its fixed `GuardedHookVault`, and a v4-style `UnlockPool`; CI requires the first to fail and the other two to pass.

### `FoundryGuard_Report.md`

`foundryguard report` and `foundryguard run --test` write a Markdown report to the project root (`--report PATH` to move it, `--no-report` to skip it). It reads `forge test --json` (one document or one object per line) and plain `forge test -vv` / `-vvv` / `-vvvv` stdout:

- PASSED / FAILED badges for the run, every suite and every test, with runs, calls, reverts and gas;
- for each broken invariant or failed fuzz test: the reason, the shrunk counter-example call sequence (sender, target, function, arguments named from the handler source), a Solidity replay test, the exact `forge test --match-test ... -vvvv` command, and the logs and traces forge printed;
- the invariant that really broke when forge files a shared campaign under another name.

```sh
forge test -vvv | foundryguard report -        # or: python3 src/cli/reporter.py forge.log
```

### `foundryguard.toml`

Run `foundryguard init` for a commented template. Settings live in the config, not in the generated files, so regenerating with `--force` keeps them:

```toml
[classify]
deposit = ["enter", "join"]
ignore = ["mintFee"]

[contracts.MyVault]
constructor_args = ["address(asset)", "\"Vault\"", "\"vTKN\""]   # mocks are named after the parameter
setup = ["vm.warp(1 days);"]
```

### CI

`foundryguard check` fails when the generated suites are out of date. `--report-md "$GITHUB_STEP_SUMMARY"` puts a summary on the workflow run, and `--sarif` lists setup warnings. To run the suites in your own repo with the bundled action:

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

Broken invariants become code-scanning alerts that point at the failing `invariant_*` function, with the call sequence in the message.

This repo tests FoundryGuard itself in `.github/workflows/foundryguard.yml`: Python unit tests on 3.9 and 3.13, then a fixture project in `tests/foundryguard/fixtures/project` (simple vault, reward staking, upgradeable vault, OpenZeppelin ERC-4626, plain token) is generated with the AST backend, built and fuzzed with Forge.

```sh
python3 -m unittest discover -s tests/foundryguard -v
```

### Limitations

- The generated suites are a strong starting point, not an audit. Add the protocol-specific invariants only you can state, using the ghost variables.
- Functions with array, struct, `bytes` or `string` parameters are listed as skipped, not fuzzed. That includes a real v4 `PoolManager` (`PoolKey` structs), so Preset 04 targets contracts with elementary-typed flows that call hooks, not the PoolManager itself. Hook addresses are not mined for v4 permission bits.
- Contract-typed constructor arguments that are not tokens (oracles, routers) get `address(this)` with a `FOUNDRYGUARD` note. Pass real mocks via `constructor_args`.
- Presets assume no external yield. Delete or relax `solvency` and the `*OutBoundedByIn` invariants for vaults that deploy into strategies or earn yield.

---

## 📜 License

MIT. See the SPDX headers in each source file.
