// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Sample {
    IERC20 public token;
    mapping(uint256 => uint256) public forVotes;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    function castVote(uint256 id) external {
        require(!hasVoted[id][msg.sender]);
        hasVoted[id][msg.sender] = true;
        forVotes[id] += token.balanceOf(msg.sender);
    }
}
