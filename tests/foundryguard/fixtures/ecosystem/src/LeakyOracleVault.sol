// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC20 } from "./IERC20.sol";
import { IPriceOracle } from "./IPriceOracle.sol";

/// @title LeakyOracleVault
/// @notice Books deposits as value (token amount times the oracle price) and pays withdrawals back in
///         tokens at the current price. On its own the contract looks consistent. Once the price falls
///         after a deposit, the vault owes more tokens than it holds: `totalAssets()` exceeds its balance.
/// @dev The defect is only visible when the oracle moves between calls, so a suite that deploys the
///      vault alone (with a placeholder oracle) cannot find it.
contract LeakyOracleVault {
    IERC20 public immutable token;
    address public oracle;

    uint256 public totalCredit;
    mapping(address => uint256) public creditOf;

    error ZeroAmount();
    error Insufficient();

    constructor(IERC20 token_, address oracle_) {
        token = token_;
        oracle = oracle_;
    }

    function deposit(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 credit = amount * IPriceOracle(oracle).price() / 1e18;
        creditOf[msg.sender] += credit;
        totalCredit += credit;
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
    }

    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 cost = amount * IPriceOracle(oracle).price() / 1e18;
        if (creditOf[msg.sender] < cost) revert Insufficient();
        creditOf[msg.sender] -= cost;
        totalCredit -= cost;
        require(token.transfer(msg.sender, amount), "transfer");
    }

    /// @notice Tokens a user can withdraw at the current price.
    function balanceOf(address user) external view returns (uint256) {
        return creditOf[user] * 1e18 / IPriceOracle(oracle).price();
    }

    /// @notice Tokens the vault owes all depositors at the current price.
    function totalAssets() external view returns (uint256) {
        return totalCredit * 1e18 / IPriceOracle(oracle).price();
    }
}
