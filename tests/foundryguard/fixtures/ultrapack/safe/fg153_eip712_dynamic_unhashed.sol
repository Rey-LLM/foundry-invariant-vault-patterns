// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract Orders is EIP712 {
    bytes32 public constant ORDER_TYPEHASH = keccak256("Order(address maker,string memo,uint256 nonce)");
    address public immutable signer;
    mapping(uint256 => bool) public used;

    constructor(address s) EIP712("Orders", "1") { signer = s; }

    function fill(address maker, string calldata memo, uint256 nonce, bytes calldata sig) external {
        require(!used[nonce], "used");
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(ORDER_TYPEHASH, maker, keccak256(bytes(memo)), nonce)));
        require(ECDSA.recover(digest, sig) == signer, "bad sig");
        used[nonce] = true;
    }
}
