// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC4626 } from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

/// @notice Stock OpenZeppelin ERC-4626 vault. Fixture for FoundryGuard tests.
contract OZVault is ERC4626 {
    constructor(IERC20 asset_) ERC20("FoundryGuard Vault", "fgV") ERC4626(asset_) { }
}
