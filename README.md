# Foundry Invariant Vault Patterns

Stateful security regression patterns for share-based vaults. Each pattern pairs a deliberately vulnerable implementation with bounded handler actions, independent accounting properties, deterministic reproductions, and a defensive control.

## Pattern 01: ERC-4626 Inflation Vulnerability Matrix

This is an executable security laboratory. The vulnerable vaults and unrestricted mock asset are test fixtures and must not be deployed with real funds.

### Architecture

```text
src/erc4626-inflation/
  MockERC4626.sol              MockAsset, vulnerable vault, withdrawal-rounding mutation
  Handler.sol                  Four actors; deposit, withdraw, and direct donation actions
test/erc4626-inflation/
  InflationInvariant.t.sol     Stateful properties, regression matrix, and protected control
foundry.toml                  Compiler, remappings, fuzzing, and invariant profiles
README.md                     Setup, expected results, and threat model
```

`MockERC4626` inherits the complete ERC-4626 and ERC-20 interfaces from OpenZeppelin, but replaces the conversion math with the unprotected fixed-point ratio. It intentionally removes virtual reserves while retaining full-precision multiplication/division, asset transfer safety, share allowances, and the standard rounding directions. `FloorWithdrawERC4626` changes only withdrawal rounding to isolate a second defect.

For nonzero supply, a deposit receives `floor(assets * totalSupply / totalAssets)` shares. At zero supply, conversion starts at one share unit per asset unit. `totalAssets()` includes direct token transfers. An attacker can therefore seed one share, donate assets, and increase the price until the next deposit rounds to zero. Flooring is required for deposits; the vulnerability is accepting extreme rounding loss without reserves or a minimum-share check.

### Setup

Install Foundry from the [official installation guide](https://getfoundry.sh/introduction/installation/). Use Forge 1.8.7 or later and the compiler pinned in `foundry.toml`.

```sh
git clone https://github.com/Rey-LLM/foundry-invariant-vault-patterns.git
cd foundry-invariant-vault-patterns
forge install foundry-rs/forge-std@v1.9.7 --no-git
forge install OpenZeppelin/openzeppelin-contracts@v5.4.0 --no-git
forge build
forge fmt --check
```

Dependencies are pinned installation inputs, not vendored files or submodules. The five tracked files form the pattern; `lib/`, `out/`, and `cache/` are local build artifacts and should not be committed.

### Run the matrix

```sh
# Passing deterministic and parameter-fuzzed reproductions
forge test --match-contract '^InflationMatrixTest$' -vv

# Passing stateful bookkeeping and defensive controls
forge test --match-contract '^(AccountingInvariant|ProtectedInvariant)$' -vv

# Expected failures: exercise each detector separately
forge test --match-contract '^InflationInvariant$' --match-test invariant_positiveDepositsReceiveShares -vvvv
forge test --match-contract '^WithdrawalRoundingInvariant$' --match-test invariant_withdrawalsBurnEnoughShares -vvvv

# Larger passing campaign
FOUNDRY_PROFILE=ci forge test --match-contract '^(InflationMatrixTest|AccountingInvariant|ProtectedInvariant)$'
```

In PowerShell, set the profile with `$env:FOUNDRY_PROFILE = 'ci'` before the command. The two detector commands intentionally exit nonzero. An unfiltered `forge test` also fails because it includes those vulnerable fixtures. Passing reproductions assert the exploit outcome explicitly; do not invert the safety properties to turn the detector suite green. Forge prints and shrinks the failing action sequence for replay.

| Scenario | Setup and action | Expected observation | Coverage |
| --- | --- | --- | --- |
| Ordinary operation | Deposit 100, withdraw 40 | 60 shares remain; 40 assets returned | Regression |
| Zero-share inflation | Seed 1, donate `u`, victim deposits `u` | Victim receives 0; attacker redeems `1 + 2u` | Parameter fuzz + failing invariant |
| Partial-share loss | Seed 2, donate 3, victim deposits 4 | Victim receives 1 share, redeems 3 | Regression |
| Empty-vault donation | Donate 100 before first deposit of 1 | First shareholder redeems 101 | Regression |
| Correct withdrawal | Supply 2, assets 3, withdraw 1 | Ceiling burns 1 share | Regression + passing invariant |
| Floor withdrawal mutation | Supply 2, assets 3, withdraw 1 | Floor burns 0 shares | Regression + failing invariant |
| Mint/redeem rounding | Supply 2, assets 3 | Mint quote rounds up; redeem quote rounds down | Regression |
| Delegated withdrawal | Unapproved caller spends another owner's shares | Reverts without changing ownership | Regression |
| Defensive control | Virtual reserves, six extra share decimals, reject zero-share deposits | Seed attack is unprofitable; zero-share transfer reverts | Regression + passing invariant |

### Stateful harness

`setUp()` calls `targetContract(address(handler))` and restricts selectors to `deposit`, `withdraw`, and `donate`. The vault and the mintable asset are not direct fuzz targets. Four fixed actors have asset allowances; each deposit or donation is independently funded. Actions are bounded to `1e24` raw asset units, including one-unit boundary cases, and run within the configured campaign depth. Each campaign starts with a one-unit seed deposit to expose low-liquidity behavior without scripting the attack inside an action.

Ghost ledgers record successful deposits, donations, and withdrawals. The asset-flow identity is `vault assets + withdrawn assets == deposited assets + donated assets`; direct donations are explicit inputs. Actor wallets plus vault assets must also equal the mock asset's supply, and actor share balances must sum to share supply. These identities can hold while users lose money, so economic properties are checked separately.

The handler records sticky counters for successful zero-share deposits and withdrawals satisfying `burnedShares * assetsBefore < withdrawnAssets * supplyBefore`. These observations survive later actions, preventing a subsequent deposit or withdrawal from hiding a defect. Preview checks also compare actual token balances and share supply changes. Positive deposits rejected with a zero-share quote leave all pre-call balances unchanged; any other deposit revert bubbles up. With `fail_on_revert = true`, unexpected handler reverts fail the campaign.

Action counters expose successful calls, rejected zero-share deposits, and empty withdrawals. A deterministic handler test covers all three actions and the skipped-withdrawal branch; another proves that both sticky detectors fire. Inspect Forge's selector metrics to judge campaign coverage. A passing campaign is bounded evidence, not a proof over all states.

### Defensive scope

`ProtectedVault`, defined in the test file, uses OpenZeppelin's virtual assets/shares with a six-decimal offset and rejects positive deposits that would mint zero shares. It is a control for this matrix, not a complete production vault. Partial rounding losses still require user-defined minimum shares or a slippage-aware router. A zero-share guard alone does not prevent partial-share inflation attacks.

The model assumes a standard non-rebasing, fee-free ERC-20; no yield, fees, privileged asset removal, callback tokens, share transfers outside the actor set, or external price feeds. Withdrawal checks use the pre-call state, and the cross-products fit within 256 bits for the configured bounded campaigns. Changing the asset model, share precision, or campaign bounds requires reviewing these assumptions.

### References

- [ERC-4626 specification](https://eips.ethereum.org/EIPS/eip-4626)
- [OpenZeppelin inflation attack analysis](https://docs.openzeppelin.com/contracts/5.x/erc4626)
- [Foundry invariant testing](https://getfoundry.sh/forge/invariant-testing/)

Solidity sources carry SPDX MIT identifiers. Dependency licenses remain with their respective projects.
