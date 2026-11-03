// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC20 } from "./IERC20.sol";
import { IPriceOracle } from "./IPriceOracle.sol";

/// @title OracleVault
/// @notice Deposits are booked in token units. The oracle only prices positions for display and
///         rejects deposits while the feed reports zero, so a price move never changes what the vault owes.
contract OracleVault {
    IERC20 public immutable token;
    IPriceOracle public immutable oracle;

    uint256 public totalDeposits;
    mapping(address => uint256) public balanceOf;

    error ZeroAmount();
    error NoPrice();
    error Insufficient();

    constructor(IERC20 token_, IPriceOracle oracle_) {
        token = token_;
        oracle = oracle_;
    }

    function deposit(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (oracle.price() == 0) revert NoPrice();
        balanceOf[msg.sender] += amount;
        totalDeposits += amount;
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
    }

    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (balanceOf[msg.sender] < amount) revert Insufficient();
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
        require(token.transfer(msg.sender, amount), "transfer");
    }

    function totalAssets() external view returns (uint256) {
        return totalDeposits;
    }

    /// @notice Value of a position in the oracle's unit.
    function valueOf(address user) external view returns (uint256) {
        return balanceOf[user] * oracle.price() / 1e18;
    }
}
