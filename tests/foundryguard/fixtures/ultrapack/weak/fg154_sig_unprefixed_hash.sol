// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Claims {
    address public immutable signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credit;

    constructor(address s) { signer = s; }

    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encode(msg.sender, amount, nonces[msg.sender]++, block.chainid, address(this)));
        address who = ecrecover(hash, v, r, s);
        require(who != address(0) && who == signer, "bad sig");
        credit[msg.sender] += amount;
    }
}
