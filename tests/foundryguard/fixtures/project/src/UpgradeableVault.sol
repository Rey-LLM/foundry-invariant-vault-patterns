// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from "./IERC20.sol";

/// @notice Initializable vault meant to sit behind a proxy. Fixture for FoundryGuard tests.
contract UpgradeableVault {
    IERC20 public asset;
    address public owner;
    bool private initialized;
    uint256 public totalDeposits;
    mapping(address => uint256) public balanceOf;

    modifier initializer() {
        require(!initialized, "initialized");
        initialized = true;
        _;
    }

    constructor() {
        initialized = true; // lock the implementation, like _disableInitializers()
    }

    function initialize(IERC20 asset_, address owner_) external initializer {
        asset = asset_;
        owner = owner_;
    }

    function deposit(uint256 amount, address receiver) external {
        require(amount > 0, "zero");
        asset.transferFrom(msg.sender, address(this), amount);
        balanceOf[receiver] += amount;
        totalDeposits += amount;
    }

    function withdraw(uint256 amount, address receiver, address owner_) external {
        require(owner_ == msg.sender, "owner");
        balanceOf[owner_] -= amount;
        totalDeposits -= amount;
        asset.transfer(receiver, amount);
    }
}
