// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract VoteToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegates;
    mapping(address => uint256) public votes;

    function delegate(address to) external {
        require(to != address(0));
        delegates[msg.sender] = to;
        votes[to] += balanceOf[msg.sender];
    }
}
