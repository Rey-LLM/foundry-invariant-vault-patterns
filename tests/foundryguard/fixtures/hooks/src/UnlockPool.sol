// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from "./IERC20.sol";

/// @notice Uniswap v4 PoolManager style callback: the caller is called back on `msg.sender`.
interface IUnlockCallback {
    function unlockCallback(bytes calldata data) external returns (bytes memory);
}

/// @notice Safe v4-style pool: deposit locks, calls the depositor back through unlockCallback before
///         touching any state, then settles. Every Preset 04 invariant must PASS on it.
contract UnlockPool {
    IERC20 public immutable token;
    bool public locked;
    uint256 public totalDeposits;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 token_) {
        token = token_;
    }

    function deposit(uint256 amount) external {
        require(!locked, "locked");
        require(amount > 0, "zero");
        locked = true;
        IUnlockCallback(msg.sender).unlockCallback(abi.encode(amount));
        token.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        totalDeposits += amount;
        locked = false;
    }

    function withdraw(uint256 amount) external {
        require(!locked, "locked");
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
        token.transfer(msg.sender, amount);
    }
}
