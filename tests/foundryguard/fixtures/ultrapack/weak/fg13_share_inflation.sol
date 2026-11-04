// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint256 public totalSupply;
    uint256 public totalAssets;

    function convertToShares(uint256 assets) public view returns (uint256) {
        return totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
    }
}
