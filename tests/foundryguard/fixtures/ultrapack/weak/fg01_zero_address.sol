// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner = msg.sender;
    address public treasury;

    function setTreasury(address t) external {
        require(msg.sender == owner);
        treasury = t;
    }
}
