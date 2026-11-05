// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Airdrop {
    bytes32 public immutable root;
    mapping(address => bool) public claimed;

    constructor(bytes32 r) { root = r; }

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[account], "claimed");
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
        require(MerkleProof.verify(proof, root, leaf), "bad proof");
        claimed[account] = true;
        payable(account).transfer(amount);
    }
}
