# Foundry Invariant Vault Patterns

Invariant test patterns for DeFi code that often breaks: vault share math, TWAP oracles and staking rewards. The repo also includes FoundryGuard, a CLI that generates invariant suites for your own contracts.

The contracts here are models and test fixtures. Some are vulnerable on purpose. Do not deploy them.

## Modules

| Module | Contract | What the invariants check |
| :-- | :-- | :-- |
| 01 ERC-4626 share inflation, `src/erc4626-inflation/` | `MockERC4626.sol`, a vault without virtual reserves | asset and share conservation, a positive deposit mints shares, withdrawals burn enough shares, results match previews |
| 02 TWAP oracle, `src/twap-validation/` | `PriceOracleModel.sol`, a cumulative-price TWAP with bounds and a 10% per-update cap | spot within bounds, cumulative matches ghost accounting, TWAP within the observed range, bounded short-window drift |
| 03 Staking rewards, `src/flashloan-reward/` | `StakingPool.sol`, a reward-per-token pool | rewards never exceed the schedule, no reward from same-block stake/unstake, `totalStaked` equals the sum of balances |

Each module has a reference contract, a handler that makes bounded valid calls and keeps ghost accounting, and an invariant test that compares the contract's state with that accounting. Two suites in module 01 fail on purpose to show the defects. `ProtectedInvariant` shows the fix.

```text
src/
  erc4626-inflation/   module 01
  twap-validation/     module 02
  flashloan-reward/    module 03
  cli/                 FoundryGuard (foundryguard.py, parser.py, ast_backend.py, injector.py, reporter.py, reporting.py)
    blueprints/        invariant presets (hook_reentrancy.py)
test/                  module tests
tests/foundryguard/    FoundryGuard unit tests and fixtures
```

## Running the modules

Install [Foundry](https://getfoundry.sh/introduction/installation/), then:

```sh
git clone https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git
cd foundry-invariant-vault-patterns
forge install foundry-rs/forge-std --no-git
forge install OpenZeppelin/openzeppelin-contracts --no-git   # module 01 only
forge test -vvv
```

Run one module with `--match-path`, for example `forge test --match-path "test/twap-validation/*"`. A failing invariant prints the call sequence that broke it; rerun with `-vvvv` for the full trace. For a deeper CI run, set `runs = 256`, `depth = 128` under `[profile.ci.invariant]` and run with `FOUNDRY_PROFILE=ci`.

To reuse a pattern, copy the closest handler and test, point the handler at your contract, and keep the ghost accounting independent of the contract's own math.

## FoundryGuard

FoundryGuard reads your Solidity, finds the functions that move value, and writes a `Handler.sol` and an `Invariant.t.sol` per contract. The generated `setUp` deploys and funds what it needs. It needs Python 3.9+ (3.9 and 3.10 also need `tomli`, which `pip install .` installs).

```sh
pipx install git+https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git
foundryguard run --test       # scan, generate, run forge test, write FoundryGuard_Report.md
```

Without installing: `python3 path/to/src/cli/foundryguard.py run`.

| Command | What it does |
| :-- | :-- |
| `foundryguard init` | writes a commented `foundryguard.toml` |
| `foundryguard scan` | Solidity to a `foundryguard.json` blueprint |
| `foundryguard gen` | blueprint to `test/foundryguard/<Contract>/` suites |
| `foundryguard run [--test]` | `scan` and `gen`; with `--test` also `forge test` and the report |
| `foundryguard check` | exits 1 when generated suites are missing or stale |
| `foundryguard report <file or ->` | `forge test --json` or `-vvv` output to `FoundryGuard_Report.md`, plus CI Markdown and SARIF |

### Scanning

The default backend reads the solc AST from `forge build --ast` (or existing Foundry, Hardhat or `solc --standard-json` output). Without a compiler it falls back to a regex parser that follows imports and remappings. Library contracts are only used to resolve inheritance. If a parent contract is missing, FoundryGuard warns instead of silently dropping its functions.

Functions are classified by name:

| Category | Names (prefix) |
| :-- | :-- |
| deposit | `deposit`, `mint`, `supply`, `fund`, `addLiquidity`, `provide`, `topUp` |
| withdraw | `withdraw`, `redeem`, `exit`, `removeLiquidity`, `burn`, `emergencyWithdraw` |
| stake in / out | `stake`, `lock`, `bond`, `createLock` / `unstake`, `unlock`, `unbond`, `cooldown` |
| reward | `claim`, `getReward`, `harvest`, `collect`, `compound` |

Add or ignore names under `[classify]` in `foundryguard.toml`.

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
| All | `afterInvariant` fails a run in which no value-flow call succeeded |

### Preset 04: hook read-reentrancy

Applies to contracts that call an external hook in the middle of a flow: Uniswap v4 hooks (`beforeSwap`, `afterAddLiquidity`, ...), `before*`/`after*` calls on a hook, `unlockCallback`, `lockAcquired` or `*Callback` on `msg.sender`, and `onFlashLoan`.

The generated suite makes every fuzz actor a `<Contract>HookProbe` and registers one as the hook (through a hook-typed constructor or initializer argument, or a `setHook`-style setter). When the contract calls out, the probe:

- reads its price and accounting views and checks they match the state before or after the flow, not something in between (`invariant_hook_readConsistency`);
- checks that the lock getter (`locked`, `reentrancyGuardEntered`, ...) reads true (`invariant_hook_lockEngagedDuringCallback`);
- tries to re-enter the running flow if it is `nonReentrant` or `lock`, and fails if that works (`invariant_hook_guardedFlowsNotReentered`).

`tests/foundryguard/fixtures/hooks` has a broken `HookedVault`, its fixed `GuardedHookVault` and a v4-style `UnlockPool`. CI requires the first to fail and the other two to pass.

### Report

`foundryguard report` and `foundryguard run --test` write `FoundryGuard_Report.md` to the project root (`--report PATH` to move it, `--no-report` to skip it). It reads forge JSON or stdout and shows PASSED/FAILED per test and, for each broken invariant, the shrunk call sequence, a Solidity replay test and the command to rerun it. Forge 1.x does not print the sequence for invariant campaigns, so the report reads it from `cache/invariant/failures/`.

```sh
forge test -vvv | foundryguard report -
```

### Config

```toml
[classify]
deposit = ["enter", "join"]
ignore = ["mintFee"]

[contracts.MyVault]
constructor_args = ["address(asset)", "\"Vault\"", "\"vTKN\""]
setup = ["vm.warp(1 days);"]
```

Settings live in the config, so regenerating with `--force` keeps them.

### CI

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

Broken invariants show up as code-scanning alerts on the failing `invariant_*` function. This repo's own workflow runs the Python tests on 3.9 and 3.13 and fuzzes the fixture projects with forge. Run the tests locally with `python3 -m unittest discover -s tests/foundryguard -v`.

### Limitations

- The suites are a starting point, not an audit. Add the protocol-specific invariants only you can state.
- Functions with array, struct, `bytes` or `string` parameters are skipped. That includes a real v4 `PoolManager`.
- Non-token contract arguments (oracles, routers) get `address(this)` with a note. Pass real mocks through `constructor_args`.
- Presets assume no external yield. Relax `solvency` and the `*OutBoundedByIn` invariants for vaults that earn yield.

## License

MIT.
