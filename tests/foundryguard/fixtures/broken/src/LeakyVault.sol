// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from "./IERC20.sol";

/// @notice Deliberately broken vault: withdraw books the full amount but pays a 1% bonus out of
///         other users' deposits. CI expects FoundryGuard's generated suite to FAIL on it, which
///         proves the generated invariants (not only the first one per contract) are enforced.
contract LeakyVault {
    IERC20 public immutable token;
    uint256 public totalDeposits;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 token_) {
        token = token_;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        token.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        totalDeposits += amount;
    }

    function withdraw(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
        uint256 payout = amount + amount / 100;
        uint256 held = token.balanceOf(address(this));
        token.transfer(msg.sender, payout > held ? held : payout);
    }
}
