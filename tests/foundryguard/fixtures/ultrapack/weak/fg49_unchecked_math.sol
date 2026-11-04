// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    function diff(uint256 a, uint256 b) external pure returns (uint256) {
        require(a >= b);
        unchecked {
            return a - b;
        }
    }
}
