// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract Faucet {
    address public immutable signer;
    mapping(address => uint256) public nonces;

    constructor(address s) { signer = s; }

    function drip(address to, uint256 amount, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encode(to, amount, nonces[to]++, block.chainid, address(this)));
        require(ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), sig) == signer, "bad sig");
        payable(to).transfer(amount);
    }
}
