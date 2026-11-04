// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Locker {
    uint256 public constant LOCK = 30 days;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public unlockAt;

    function depositFor(address user) external payable {
        require(user == msg.sender, "self only");
        balances[user] += msg.value;
        unlockAt[user] = block.timestamp + LOCK;
    }
}
