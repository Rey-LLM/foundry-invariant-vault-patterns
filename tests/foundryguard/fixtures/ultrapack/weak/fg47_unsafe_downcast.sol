// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint128 public stored;

    function store(uint256 a) external {
        require(a != 0);
        stored = uint128(a);
    }
}
