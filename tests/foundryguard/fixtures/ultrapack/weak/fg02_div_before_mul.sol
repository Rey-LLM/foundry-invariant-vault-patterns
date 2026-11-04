// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    function quote(uint256 a, uint256 b) external pure returns (uint256) {
        require(b > 0);
        return a / b * 3;
    }
}
