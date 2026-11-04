# Foundry Invariant Vault Patterns

Invariant test patterns for DeFi code that often breaks: vault share math, TWAP oracles, staking rewards and EIP-1153 transient storage. The repo also includes FoundryGuard, a CLI that generates invariant suites for your own contracts.

The contracts here are models and test fixtures. Some are vulnerable on purpose. Do not deploy them.

## Modules

| Module | Contract | What the invariants check |
| :-- | :-- | :-- |
| 01 ERC-4626 share inflation, `src/erc4626-inflation/` | `MockERC4626.sol`, a vault without virtual reserves | asset and share conservation, a positive deposit mints shares, withdrawals burn enough shares, results match previews |
| 02 TWAP oracle, `src/twap-validation/` | `PriceOracleModel.sol`, a cumulative-price TWAP with bounds and a 10% per-update cap | spot within bounds, cumulative matches ghost accounting, TWAP within the observed range, bounded short-window drift |
| 03 Staking rewards, `src/flashloan-reward/` | `StakingPool.sol`, a reward-per-token pool | rewards never exceed the schedule, no reward from same-block stake/unstake, `totalStaked` equals the sum of balances |
| 05 Transient storage, `src/transient-vault/` | `TransientStaking.sol`, daily staking points with a transient lock and entry bonus, and `LeakyTransientStaking`, which never clears the entry slot | every transient slot is zero again after each call and between the steps of a multicall, stake and point totals match the sum of balances, token solvency |

Each module has a reference contract, a handler that makes bounded valid calls and keeps ghost accounting, and an invariant test that compares the contract's state with that accounting. Two suites in module 01 fail on purpose to show the defects. `ProtectedInvariant` shows the fix.

Module 05 is about a mistake that is easy to make with `TSTORE`: EIP-1153 clears transient storage when the transaction ends, not when the call returns. So a test that looks at the slots after the transaction always passes. The bug shows up inside the transaction, when the next call (a multicall step, a router hop, a callback) reads a value the previous call left behind. The handler therefore runs several calls in one transaction and reads the slots after each of them. `LeakyTransientStakingTest` shows the effect: in `multicall([stake, claimPoints, claimPoints])` the leaky version pays the entry bonus three times.

```text
src/
  erc4626-inflation/   module 01
  twap-validation/     module 02
  flashloan-reward/    module 03
  transient-vault/     module 05
  cli/                 FoundryGuard (foundryguard.py, compiler.py, parser.py, injector.py, ai_generator.py, reporter.py, reporting.py,
                       scoring.py for the 1-100 score, gui.py for the desktop window)
                       parser.py also builds the cross-contract dependency matrix, injector.py the ecosystem suites
    blueprints/        invariant presets (hook_reentrancy.py, transient_storage.py)
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

FoundryGuard compiles your Solidity, finds the functions that move value in the compiler's AST, and writes a `Handler.sol` and an `Invariant.t.sol` per contract. Contracts that depend on each other (a vault and its oracle, a vault and its strategy) get one suite for the whole group instead. The generated `setUp` deploys, wires and funds what it needs. It needs Python 3.9+ (3.9 and 3.10 also need `tomli`, which `pip install .` installs) and a Solidity compiler: solc, solcjs or Foundry.

```sh
pipx install git+https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git
foundryguard run --test       # scan, generate, run forge test, write FoundryGuard_Report.md
```

Without installing: `python3 path/to/src/cli/foundryguard.py run`.

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
| `foundryguard bridge <path>` | the seam between backend and contracts: who can make the server key sign or send, and whether the contract enforces what the backend signs |
| `foundryguard-gui [path or URL]` | desktop window that runs the score, the preset matrix and, with forge installed, the fuzzing (`foundryguard gui` does the same) |

`pipx install` puts `foundryguard`, `foundryguard-gui` and `foundryguard-bridge` on PATH, so they work from any directory.

### How it fits together

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
| 13 | `signatures.py` | the signature database (FG-01 to FG-15) |

### Scanning

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

### Report

`foundryguard report` and `foundryguard run --test` write `FoundryGuard_Report.md` to the project root (`--report PATH` to move it, `--no-report` to skip it). It reads forge JSON or stdout and shows PASSED/FAILED per test and, for each broken invariant, the shrunk call sequence, a Solidity replay test and the command to rerun it. Forge 1.x does not print the sequence for invariant campaigns, so the report reads it from `cache/invariant/failures/`.

The same results also go to `foundryguard-report.html` next to the Markdown file (`--html PATH` to move it, `--no-html` to skip it). It is one static page with no scripts or external files: run metrics, a table per suite, and each failed execution path as a collapsible tree of calls with sender, target, named parameters and, when the trace has them (`-vvvvv`), the storage slots each call changed. The last node is the invariant check with both sides of the failed assertion and their difference.

The metrics count each invariant campaign once. Forge 1.x runs all invariants of a test contract in one campaign and prints its stats on every one of them, so adding them up per test would multiply the calls. Fuzz inputs are invariant handler calls plus fuzz runs. Execution time is forge's own wall clock from stdout; JSON output has no wall clock, so the report shows the sum of suite durations and says so.

```sh
forge test -vvv | foundryguard report -
```

### Score and desktop window

`foundryguard score` and the `foundryguard-gui` window rate a codebase from 1 to 100. The score starts at 100 and every finding takes points off: CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3. One rule can take at most three times its weight, so the same mistake repeated a hundred times does not hide everything else. The floor is 1. The scale is strict on purpose: a function that takes an amount and never checks it, a privileged variable anyone can set, or a state write after an external call each cost 15 to 25 points.

Each deduction lists the file and line, the severity, the layer (L1 input validation, L2 access control, L3 mutability, L4 state drift, L5 external calls, L6 injection, L7 secrets, L8 transport, L9 configuration, L10 fuzzed invariant) and what to do about it. The report ends with a mitigation plan grouped by rule.

What it reads:

- Solidity: missing input checks, unprotected writes to owner/fee/oracle-style variables, `tx.origin`, unguarded initializers, functions that could be `view`, `payable` functions that ignore `msg.value`, writes after an external call, unchecked low-level calls, delegatecall targets, spot prices and stale oracle reads, votes weighed by live balance, first-depositor share math, division by a total that can be zero, unfunded reward schedules, transient slots that are never cleared, weak randomness, division before multiplication. Rules tied to a preset follow the preset toggles.
- Backend and site code (`.py`, `.js`/`.ts`, `.html`, `.php`): string-built SQL, shell commands, `eval`, unsafe deserialization, request input with no validation library in the file, secrets in source, TLS checks turned off, XSS sinks, POST forms without a CSRF token, tokens in `localStorage`, debug mode, wildcard CORS, mutable global state.
- A URL: one GET of the page. The response headers (CSP, HSTS, framing, cookie flags, version banners) and the returned HTML and inline scripts are checked. Nothing else is requested and nothing is fuzzed against the host, so only point it at sites you own or may test.

`test`, `lib`, `node_modules`, `script` and build folders are skipped, as are `*.t.sol` files.

For Solidity the report also has a simulation matrix: one row per contract, one column per preset. ARMED means the AST detectors that `foundryguard gen` uses would generate that suite; FLAGGED means a scoring rule for that preset matched. With `--fuzz` (on by default in the window), forge on PATH and a `foundry.toml` above the target, it runs `foundryguard run --test`; every broken invariant becomes a CRITICAL L10 deduction and the forge results are embedded in the same page.

```sh
foundryguard score .                        # score the project, write foundryguard-report.html
foundryguard score . --fuzz --min-score 75  # also fuzz with forge; exit 1 below 75 (for CI)
foundryguard score src/Vault.sol --presets 1,4,8 --json
foundryguard score https://app.example.com  # one passive GET; report goes to ~/foundryguard-reports/<host>/
foundryguard-gui                            # the window
```

The window is built on customtkinter (installed with the package; Tk itself comes from `python3-tk` on Debian and Ubuntu, the python.org installers ship it). Dark theme: one bar for a folder, a file or a URL, the eight presets as a 4 x 2 grid, and LAUNCH SECURITY SIMULATION. The run happens in a background thread with a progress bar and elapsed time, so the window stays responsive and Stop works. When it finishes, the score card turns green, amber or red and the report opens in the browser with the score at the top. `foundryguard-score.json` next to it has the same data for scripts.

### Backend to contract bridge

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

### Signature database

Fifteen signatures sit on top of the score rules. Each has a fixed cost, a CWE or SWC reference and a fix example, and every hit in the report and in `--json` carries its id.

| ID | Stack | Rule | Severity | Catches |
| :-- | :-- | :-- | :-- | :-- |
| FG-01 | Solidity | `SOL-ZERO-ADDRESS` | HIGH | address parameter stored without an `address(0)` check |
| FG-02 | Solidity | `SOL-DIV-BEFORE-MUL` | HIGH | `a / b * c` precision loss |
| FG-03 | Solidity | `SOL-TX-ORIGIN` | CRITICAL | `tx.origin` used for authorization |
| FG-04 | Solidity | `SOL-WEAK-RANDOMNESS` | HIGH | randomness from `block.timestamp`, `prevrandao`, `blockhash` (hashed or `%`) |
| FG-05 | Solidity | `SOL-UNCHECKED-CALL` | HIGH | `.call` / `.send` result ignored |
| FG-06 | Solidity | `SOL-ERC20-UNCHECKED` | HIGH | ERC-20 `transfer` / `transferFrom` / `approve` bool ignored |
| FG-07 | Solidity | `SOL-ARBITRARY-FROM` | CRITICAL | `transferFrom(from, ...)` with `from` chosen by the caller |
| FG-08 | Solidity | `SOL-UNBOUNDED-LOOP` | HIGH | entry point loops over a whole storage array |
| FG-09 | Backend | `WEB-SECRET` | CRITICAL | private keys, API keys and tokens in source |
| FG-10 | Backend | `WEB-WEAK-RANDOM` | HIGH | `Math.random()` / `random` in token, nonce or password code |
| FG-11 | Backend | `WEB-BODY-LIMIT` | HIGH | Flask without `MAX_CONTENT_LENGTH`, multer without `limits`, body parsers above 50 MB |
| FG-12 | Backend | `WEB-RATE-LIMIT` | HIGH | login, signup, reset, OTP or token routes with no rate limiter anywhere in the project |
| FG-13 | Backend | `WEB-CORS-ANY` | HIGH | wildcard CORS |
| FG-14 | Backend | `WEB-EVAL` | CRITICAL | `eval`, `exec`, `new Function` |
| FG-15 | Backend | `WEB-COMMAND` | CRITICAL | shell commands built at runtime (`os.system`, `child_process`, `shell=True`) |

CRITICAL costs 25 points and HIGH 15, with the same three-hits-per-rule cap as the rest of the score. The Layer 12 rules for a seed phrase or RPC key in source count as FG-09, and weak signature nonces as FG-10. The report has a Signature database table (matched rows in black, the rest greyed out) and the mitigation plan prints each fix example under its rule.

FG-06, FG-07, FG-08, FG-11 and FG-12 are new in 0.14; run over OpenZeppelin, Solady and this repo's modules they report nothing. Like the other score rules they read source text, not data flow, so tune them per project:

```toml
[score]
ignore = ["src/legacy/**", "frontend/vendor/*"]   # globs relative to the scanned folder
max_depth = 8                                     # folder levels below the target (0 = the target folder only)

[score.severity]
"FG-02" = "MEDIUM"        # by signature id
"WEB-RATE-LIMIT" = "off"  # or by rule name; works for every rule, not only the fifteen
```

`foundryguard score` and the window read the nearest `foundryguard.toml` at or above the target; `--config` points at another one.

### Config

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

Broken invariants show up as code-scanning alerts on the failing `invariant_*` function. This repo's own workflow runs the Python tests on 3.9 and 3.13 with solc 0.8.24, fuzzes the fixture projects with forge (including the ecosystem one), maps this repo's modules and runs module 05, and resolves OpenZeppelin and Solady parents through both the solc and forge drivers, and breaks a generated handler on purpose to check that `foundryguard heal` gets it building again with forge. Run the tests locally with `python3 -m unittest discover -s tests/foundryguard -v`. Tests that compile are skipped when no solc or solcjs is installed; the OpenZeppelin/Solady ones also need `npm install` in `tests/foundryguard/fixtures/libs`.

### Limitations

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

## License

MIT.
