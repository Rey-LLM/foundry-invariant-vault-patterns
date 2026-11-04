// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }

contract Rewards {
    IERC20 public rewardToken;
    mapping(address => uint256) public rewards;

    function claim() external {
        uint256 r = rewards[msg.sender];
        require(r > 0);
        require(rewardToken.transfer(msg.sender, r));
    }
}
