// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// EIP-712 claims done right: domain bound to chain and contract, nonce consumed, deadline enforced,
/// zero signer rejected.
contract SafeClaim {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant CLAIM_TYPEHASH =
        keccak256("Claim(address account,uint256 amount,uint256 nonce,uint256 deadline)");

    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public paid;

    error Expired();
    error BadNonce();
    error BadSignature();

    constructor(address signer_) {
        require(signer_ != address(0), "signer");
        signer = signer_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("SafeClaim")), keccak256(bytes("1")), block.chainid, address(this))
        );
    }

    function claim(address account, uint256 amount, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external
    {
        if (block.timestamp > deadline) revert Expired();
        if (nonce != nonces[account]++) revert BadNonce();
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, account, amount, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address who = ecrecover(digest, v, r, s);
        if (who == address(0) || who != signer) revert BadSignature();
        paid[account] += amount;
    }
}
