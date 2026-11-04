// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint256 public totalStaked;

    function share(uint256 a) external view returns (uint256) {
        return a * 1e18 / totalStaked;
    }
}
