// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Distributor {
    address[] public stakers;
    mapping(address => uint256) public stakeOf;
    mapping(address => uint256) public rewards;
    uint256 public totalStaked;

    function distribute(uint256 amount) external {
        require(amount > 0);
        for (uint256 i = 0; i < stakers.length; i++) {
            rewards[stakers[i]] += amount * stakeOf[stakers[i]] / totalStaked;
        }
    }
}
