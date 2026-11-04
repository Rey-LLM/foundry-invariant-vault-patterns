// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IVotes { function getPastVotes(address, uint256) external view returns (uint256); }

contract Gov {
    IVotes public token;
    mapping(uint256 => uint256) public snapshot;
    mapping(uint256 => uint256) public forVotes;

    function castVote(uint256 id) external {
        require(snapshot[id] != 0);
        forVotes[id] += token.getPastVotes(msg.sender, snapshot[id]);
    }
}
