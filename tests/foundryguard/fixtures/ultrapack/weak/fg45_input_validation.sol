// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint256 public value;

    function set(uint256 v) external {
        value = v;
    }
}
