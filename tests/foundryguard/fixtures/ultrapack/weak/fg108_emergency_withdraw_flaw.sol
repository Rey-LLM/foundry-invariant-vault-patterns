// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }

contract Pool {
    IERC20 public stakingToken;
    IERC20 public rewardToken;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;

    function emergencyWithdraw() external {
        uint256 amt = balances[msg.sender];
        require(stakingToken.transfer(msg.sender, amt));
        require(rewardToken.transfer(msg.sender, rewards[msg.sender]));
    }
}
