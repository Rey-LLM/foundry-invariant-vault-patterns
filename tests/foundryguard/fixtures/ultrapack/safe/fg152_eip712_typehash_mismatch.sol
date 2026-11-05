// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract Permit is EIP712 {
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() EIP712("Permit", "1") {}

    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        require(ECDSA.recover(_hashTypedDataV4(structHash), sig) == owner, "bad sig");
        allowance[owner][spender] = value;
    }
}
