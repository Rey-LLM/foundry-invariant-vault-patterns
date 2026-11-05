// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract Faucet {
    address public immutable signer;
    mapping(bytes32 => bool) public spent;

    constructor(address s) { signer = s; }

    function drip(address to, uint256 amount, bytes32 digest, bytes calldata sig) external {
        require(!spent[digest], "spent");
        require(ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), sig) == signer, "bad sig");
        spent[digest] = true;
        payable(to).transfer(amount);
    }
}
