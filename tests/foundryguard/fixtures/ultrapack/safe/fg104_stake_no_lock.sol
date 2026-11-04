// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Staking {
    uint256 public constant LOCK_PERIOD = 7 days;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public stakedAt;

    function stake() external payable {
        balances[msg.sender] += msg.value;
        stakedAt[msg.sender] = block.timestamp;
    }

    function unstake(uint256 amount) external {
        require(block.timestamp >= stakedAt[msg.sender] + LOCK_PERIOD, "locked");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
