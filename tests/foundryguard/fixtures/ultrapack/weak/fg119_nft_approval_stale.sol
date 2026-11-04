// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MiniNFT {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;

    function transferFrom(address from, address to, uint256 id) external {
        require(from == ownerOf[id], "from");
        require(msg.sender == from || msg.sender == getApproved[id], "auth");
        require(to != address(0));
        ownerOf[id] = to;
    }
}
