// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Timelock {
    uint256 public constant MIN_DELAY = 10 minutes;
    mapping(bytes32 => uint256) public eta;

    function queue(bytes32 id) external {
        eta[id] = block.timestamp + MIN_DELAY;
    }
}
