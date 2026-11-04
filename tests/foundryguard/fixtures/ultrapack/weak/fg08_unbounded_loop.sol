// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint256[] public items;
    uint256 public total;

    function add(uint256 v) external {
        require(v > 0);
        items.push(v);
    }

    function sum() external {
        uint256 s;
        for (uint256 i = 0; i < items.length; i++) {
            s += items[i];
        }
        total = s;
    }
}
