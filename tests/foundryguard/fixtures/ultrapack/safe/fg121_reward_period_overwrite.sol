// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Rewards {
    address public owner = msg.sender;
    uint256 public constant DURATION = 7 days;
    uint256 public rewardRate;
    uint256 public periodFinish;

    function notifyRewardAmount(uint256 reward) external {
        require(msg.sender == owner);
        if (block.timestamp < periodFinish) {
            reward += (periodFinish - block.timestamp) * rewardRate;
        }
        rewardRate = reward / DURATION;
        periodFinish = block.timestamp + DURATION;
    }
}
