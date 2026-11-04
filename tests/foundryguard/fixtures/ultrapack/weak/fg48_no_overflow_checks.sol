// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract Ledger {
    uint256 public total;

    function add(uint256 a) external {
        require(a > 0);
        total = total + a;
    }
}
