// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Distributor {
    uint256 public rewardPerTokenStored;
    uint256 public totalStaked;

    function distribute(uint256 amount) external {
        require(amount > 0 && totalStaked > 0);
        rewardPerTokenStored += amount * 1e18 / totalStaked;
    }
}
