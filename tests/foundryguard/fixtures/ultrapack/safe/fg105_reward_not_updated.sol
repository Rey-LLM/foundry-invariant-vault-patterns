// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Rewards {
    uint256 public rewardPerTokenStored;
    uint256 public totalStaked;
    mapping(address => uint256) public balances;

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerTokenStored + 1;
        _;
    }

    function stake(uint256 amount) external updateReward(msg.sender) {
        require(amount > 0);
        totalStaked += amount;
        balances[msg.sender] += amount;
    }
}
