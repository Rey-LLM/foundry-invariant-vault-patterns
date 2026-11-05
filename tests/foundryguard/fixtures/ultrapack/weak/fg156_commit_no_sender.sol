// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Guess {
    mapping(address => bytes32) public commitments;
    bytes32 public immutable answerHash;

    constructor(bytes32 h) { answerHash = h; }

    function commit(bytes32 c) external {
        commitments[msg.sender] = c;
    }

    function reveal(uint256 guess, bytes32 salt) external {
        require(commitments[msg.sender] == keccak256(abi.encode(guess, salt)), "bad reveal");
        delete commitments[msg.sender];
        if (keccak256(abi.encode(guess)) == answerHash) payable(msg.sender).transfer(address(this).balance);
    }
}
