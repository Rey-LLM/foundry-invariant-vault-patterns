// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Drop {
    address public signer;
    mapping(bytes32 => bool) public used;
    mapping(address => uint256) public claimed;

    function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);
        bytes32 id = keccak256(abi.encodePacked(r, s, v));
        require(!used[id]);
        used[id] = true;
        address who = ecrecover(digest, v, r, s);
        require(who != address(0) && who == signer);
        claimed[who] += 1;
    }
}
