// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner = msg.sender;
    uint256 public rewardRate;

    function notifyRewardAmount(uint256 r) external {
        require(msg.sender == owner);
        rewardRate = r / 7 days;
    }
}
