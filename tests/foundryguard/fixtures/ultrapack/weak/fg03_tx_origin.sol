// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner = msg.sender;
    uint256 public x;

    function set(uint256 v) external {
        require(tx.origin == owner);
        x = v;
    }
}
