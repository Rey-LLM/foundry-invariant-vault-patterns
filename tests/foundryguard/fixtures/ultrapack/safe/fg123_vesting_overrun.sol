// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Vesting {
    uint256 public start;
    uint256 public duration;
    uint256 public total;

    function vestedAmount() public view returns (uint256) {
        if (block.timestamp >= start + duration) return total;
        return total * (block.timestamp - start) / duration;
    }
}
