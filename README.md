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

> 📌 **Module status.** Modules 02 and 03 are on `main`. Module 01 is under review in [PR #1](https://github.com/Rey-LLM/foundry-invariant-vault-patterns/pull/1) (`pattern-01-erc4626-inflation-matrix`), which also adds the shared `foundry.toml`. Its handler lives in `src/`, and two of its invariant suites are **expected to fail**: they demonstrate the inflation and rounding defects, while `ProtectedInvariant` shows the fix.

### 📂 Layout

```text
src/
├── erc4626-inflation/     Module 01 (PR #1)
├── twap-validation/       Module 02 · PriceOracleModel.sol
└── flashloan-reward/      Module 03 · StakingPool.sol
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

Dependencies are installed into `lib/` and are not committed. Until PR #1 lands, `main` has no `foundry.toml`, and Forge's defaults (`src/`, `test/`, `lib/`) are enough for Modules 02 and 03.

### 3. Run a module

```sh
# Module 02: TWAP oracle stability
forge test --match-path "test/twap-validation/*" -vvv

# Module 03: staking & flash-loan reward accounting
forge test --match-path "test/flashloan-reward/*" -vvv

# Module 01: ERC-4626 inflation matrix (after PR #1 is merged)
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

## 📜 License

MIT. See the SPDX headers in each source file.
