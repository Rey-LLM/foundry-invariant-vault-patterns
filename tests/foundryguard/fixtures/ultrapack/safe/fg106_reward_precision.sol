// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Rewards {
    uint256 public accRewardPerShare;
    uint256 public totalStaked;

    function addReward(uint256 amount) external {
        require(totalStaked > 0);
        accRewardPerShare += amount * 1e18 / totalStaked;
    }
}
