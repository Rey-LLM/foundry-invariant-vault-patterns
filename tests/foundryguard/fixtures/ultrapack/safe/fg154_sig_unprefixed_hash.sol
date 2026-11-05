// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract Claims {
    address public immutable signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credit;

    constructor(address s) { signer = s; }

    function claim(uint256 amount, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encode(msg.sender, amount, nonces[msg.sender]++, block.chainid, address(this)));
        require(ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(hash), sig) == signer, "bad sig");
        credit[msg.sender] += amount;
    }
}
