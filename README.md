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
└── cli/                   FoundryGuard · parser.py · injector.py
test/
├── erc4626-inflation/     InflationInvariant.t.sol
├── twap-validation/       OracleHandler.sol · OracleInvariant.t.sol
└── flashloan-reward/      RewardHandler.sol · RewardInvariant.t.sol
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

FoundryGuard turns any Foundry project into a fuzzing target in two commands. It scans your Solidity sources, finds the functions that move value, and writes a tailored `Handler.sol` and `Invariant.t.sol` for each contract, following the same handler + ghost-accounting pattern as the modules above.

It needs only Python 3.9+ and the standard library.

### Workflow

```text
src/**/*.sol ──▶ parser.py ──▶ foundryguard.json ──▶ injector.py ──▶ test/foundryguard/<Contract>/
                 (scan + classify)   (blueprint)       (generate)      Handler.sol · Invariant.t.sol
```

```sh
# 1. Scan src/ (or contracts/) and write the blueprint
python3 src/cli/parser.py -o foundryguard.json

# 2. Generate handler + invariant suites from the blueprint
python3 src/cli/injector.py foundryguard.json --out test/foundryguard

# 3. Review the setUp, then fuzz
forge test --match-path "test/foundryguard/*" --show-metrics -vvv
```

### Step 1 · `parser.py`: scan and classify

- Scans `src/` and `contracts/` by default (or the paths you pass), skipping `lib/`, `node_modules/`, `test/`, `script/` and build output.
- Strips comments and masks string literals, then extracts every contract, abstract contract, interface and library, with each function's parameters, return values, visibility, mutability and modifiers.
- Follows imports through `foundry.toml` / `remappings.txt` remappings, so functions inherited from libraries such as OpenZeppelin's `ERC4626` are known to the injector. Imported library contracts are recorded as `external` and never become test targets. Files that import `forge-std` are flagged as test helpers and skipped too.
- Classifies public and external state-changing functions by name:

| Category | Direction | Matches (prefix, case-insensitive) |
| :-- | :-- | :-- |
| `deposit` | in | `deposit`, `mint`, `supply`, `fund`, `addLiquidity`, `provide`, `topUp` |
| `withdraw` | out | `withdraw`, `redeem`, `exit`, `removeLiquidity`, `burn`, `emergencyWithdraw` |
| `stake_lock` | in | `stake`, `lock`, `bond`, `createLock`, `increaseLock`, `extendLock`, ... |
| `stake_lock` | out | `unstake`, `unlock`, `unbond`, `withdrawStake`, `cooldown`, ... |
| `stake_lock` | reward | `claim`, `getReward`, `harvest`, `collect`, `compound` |

- Detects the amount parameter (`amount`, `assets`, `shares`, `value`, ... or the only `uint` argument) and its unit: `assets`, `shares`, or `native` for payable functions that take no amount.
- Records accounting getters (`totalSupply`, `totalAssets`, `totalStaked`, `balanceOf`, ...), including public state variables.

```sh
python3 src/cli/parser.py src/flashloan-reward -o - | jq '.contracts[] | {name, categories}'
```

Key options: `--root <dir>` (project root), `-o -` (stdout), `--no-follow-imports`, `-v`.

### Step 2 · `injector.py`: generate the suites

For each deployable contract with at least one drivable value-flow function it writes `test/foundryguard/<Contract>/Handler.sol` and `Invariant.t.sol`:

- **Handler.** One wrapper per value-flow function plus a `warp` action. A fixed actor set is pranked as the caller, amounts are bounded to `[1, MAX_AMOUNT]`, address parameters (receivers, owners) are routed back to actors, and payable functions get funded with `vm.deal`. Every call runs in `try/catch`: ghost totals (`ghost_in`, `ghost_out`, per unit) move only on success, and reverts are counted per action, so the suite stays usable with `fail_on_revert = true`.
- **Invariant test.** Deploys the target, wires the handler with `targetContract` / `targetSelector`, and emits only the properties the blueprint supports:
  - `invariant_withdrawalsBoundedByDeposits`: when all flows share one unit and both directions exist (skipped for mixed-unit surfaces like ERC-4626, where the totals are not comparable).
  - `invariant_actorBalancesBoundedByTotal`: when the contract exposes a `balanceOf`-style getter and a `total*` getter.
  - `afterInvariant`: fails a run in which no value-flow call ever succeeded, which means `setUp` still needs funding or approvals.

Functions with non-elementary parameters (arrays, structs, `bytes`, `string`) are listed as skipped in the report and in the handler's NatSpec.

Key options: `--contract <Name>` (repeatable), `--out <dir>`, `--actors <n>`, `--max-amount 1e24`, `--dry-run`, `--json`, `--force` (existing files are never overwritten without it).

### After generating

The output is a starting point, not a finished audit:

1. Replace the placeholder constructor arguments marked `FOUNDRYGUARD` in `setUp` with real dependencies (tokens, oracles, owners).
2. If the target pulls ERC-20 tokens, mint to and approve from each handler actor in `setUp`.
3. Add the protocol-specific invariants that only you can state, using the generated ghost variables.

---

## 📜 License

MIT. See the SPDX headers in each source file.
