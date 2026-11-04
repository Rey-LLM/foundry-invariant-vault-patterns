// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract NameDrop {
    address public signer;
    mapping(bytes32 => bool) public used;

    function claim(string calldata name, string calldata tag, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encodePacked(name, tag));
        require(!used[h]);
        used[h] = true;
        address a = ecrecover(h, v, r, s);
        require(a != address(0) && a == signer);
    }
}
