// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from "./IERC20.sol";
import { IVaultHooks } from "./IVaultHooks.sol";

/// @notice The fixed version of HookedVault: checks-effects-interactions (the hook runs after every
///         state change), a `nonReentrant` lock exposed through `locked`, and an owner-set hook.
///         Every Preset 04 invariant must PASS on it.
contract GuardedHookVault {
    IERC20 public immutable asset;
    address public immutable owner;
    IVaultHooks public hooks;
    bool public locked;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor(IERC20 asset_) {
        asset = asset_;
        owner = msg.sender;
    }

    function setHooks(IVaultHooks hooks_) external {
        require(msg.sender == owner, "owner");
        hooks = hooks_;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function pricePerShare() external view returns (uint256) {
        return totalSupply == 0 ? 1e18 : totalAssets() * 1e18 / totalSupply;
    }

    function deposit(uint256 assets) external nonReentrant returns (uint256 shares) {
        if (address(hooks) != address(0)) {
            require(hooks.beforeDeposit(msg.sender, assets) == IVaultHooks.beforeDeposit.selector, "hook");
        }
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : assets * supply / totalAssets();
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply = supply + shares;
        balanceOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external nonReentrant returns (uint256 assets) {
        require(shares > 0 && shares <= balanceOf[msg.sender], "shares");
        assets = shares * totalAssets() / totalSupply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        asset.transfer(msg.sender, assets);
        if (address(hooks) != address(0)) {
            require(hooks.afterWithdraw(msg.sender, assets) == IVaultHooks.afterWithdraw.selector, "hook");
        }
    }
}
