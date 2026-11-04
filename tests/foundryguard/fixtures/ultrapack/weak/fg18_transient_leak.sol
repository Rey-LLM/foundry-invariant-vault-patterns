// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    function enter() external {
        assembly {
            tstore(0, 1)
        }
    }
}
