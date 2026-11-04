// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    uint256 public total;

    function credit() external {
        require(msg.data.length >= 68);
        uint256 a;
        assembly {
            a := calldataload(36)
        }
        total += a;
    }
}
