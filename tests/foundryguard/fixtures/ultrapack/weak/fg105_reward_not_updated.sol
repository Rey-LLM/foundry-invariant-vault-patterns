// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Rewards {
    uint256 public rewardPerTokenStored;
    uint256 public totalStaked;
    mapping(address => uint256) public balances;

    function stake(uint256 amount) external {
        require(amount > 0);
        totalStaked += amount;
        balances[msg.sender] += amount;
    }
}
