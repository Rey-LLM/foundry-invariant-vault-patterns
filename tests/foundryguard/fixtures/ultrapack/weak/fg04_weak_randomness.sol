// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    function roll() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 6;
    }
}
