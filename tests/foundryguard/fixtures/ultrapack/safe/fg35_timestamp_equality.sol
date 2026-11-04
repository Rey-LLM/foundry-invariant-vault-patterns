// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint256 public saleStart;
    uint256 public sold;

    function buy() external payable {
        require(block.timestamp >= saleStart);
        sold += msg.value;
    }
}
