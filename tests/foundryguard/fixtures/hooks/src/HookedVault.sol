// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from "./IERC20.sol";
import { IVaultHooks } from "./IVaultHooks.sol";

/// @notice Deliberately broken hooked vault (read-only reentrancy): withdraw pays the assets out and
///         runs the afterWithdraw hook BEFORE it burns the shares. Inside the hook totalAssets() has
///         already dropped while totalSupply has not, so pricePerShare() is too low and any protocol
///         that prices the share from inside the hook is manipulated. CI expects FoundryGuard's
///         invariant_hook_readConsistency to FAIL on it.
contract HookedVault {
    IERC20 public immutable asset;
    IVaultHooks public immutable hooks;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 asset_, IVaultHooks hooks_) {
        asset = asset_;
        hooks = hooks_;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function pricePerShare() external view returns (uint256) {
        return totalSupply == 0 ? 1e18 : totalAssets() * 1e18 / totalSupply;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(hooks.beforeDeposit(msg.sender, assets) == IVaultHooks.beforeDeposit.selector, "hook");
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : assets * supply / totalAssets();
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply = supply + shares;
        balanceOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && shares <= balanceOf[msg.sender], "shares");
        assets = shares * totalAssets() / totalSupply;
        asset.transfer(msg.sender, assets);
        // BUG: the hook runs while the shares are still outstanding.
        require(hooks.afterWithdraw(msg.sender, assets) == IVaultHooks.afterWithdraw.selector, "hook");
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
    }
}
