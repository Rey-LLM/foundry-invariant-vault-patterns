// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC4626 } from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Test asset with unrestricted minting. Never use as a production token.
contract MockAsset is ERC20 {
    constructor() ERC20("Mock Asset", "ASSET") { }

    function mint(address receiver, uint256 assets) external {
        _mint(receiver, assets);
    }
}

/// @notice Deliberately vulnerable vault: donations affect pricing without virtual reserves.
/// @dev Shares and assets have the same precision; a positive deposit can mint zero shares.
contract MockERC4626 is ERC4626 {
    constructor(IERC20 asset_) ERC20("Vulnerable Vault Share", "vASSET") ERC4626(asset_) { }

    function _convertToShares(uint256 assets, Math.Rounding rounding) internal view override returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : Math.mulDiv(assets, supply, totalAssets(), rounding);
    }

    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view override returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? shares : Math.mulDiv(shares, totalAssets(), supply, rounding);
    }
}

/// @notice Separate mutation for detecting withdrawals that burn too few shares.
contract FloorWithdrawERC4626 is MockERC4626 {
    constructor(IERC20 asset_) MockERC4626(asset_) { }

    function previewWithdraw(uint256 assets) public view override returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }
}
