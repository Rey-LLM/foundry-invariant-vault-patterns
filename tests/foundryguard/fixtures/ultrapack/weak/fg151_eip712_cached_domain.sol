// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Voucher {
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Voucher")), keccak256(bytes("1")), block.chainid, address(this)));
    }
}
