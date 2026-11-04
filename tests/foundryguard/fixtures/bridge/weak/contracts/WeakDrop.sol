// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Mints against a backend signature. Deliberately broken: the digest has no nonce, no chain id,
/// no contract address and no deadline, and the signer comes from a bare ecrecover.
contract WeakDrop {
    address public signer;
    mapping(address => uint256) public minted;

    constructor(address signer_) {
        signer = signer_;
    }

    function mintWithSig(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 inner = keccak256(abi.encodePacked(to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        address who = ecrecover(digest, v, r, s);
        require(who == signer, "bad signature");
        minted[to] += amount;
    }
}
