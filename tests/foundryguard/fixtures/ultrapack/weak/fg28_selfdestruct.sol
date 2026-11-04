// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner = msg.sender;

    function kill() external {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }
}
