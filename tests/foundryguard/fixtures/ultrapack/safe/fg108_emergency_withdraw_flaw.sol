// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }

contract Pool {
    IERC20 public stakingToken;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public totalStaked;

    function emergencyWithdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        rewards[msg.sender] = 0;
        totalStaked -= amt;
        require(stakingToken.transfer(msg.sender, amt));
    }
}
