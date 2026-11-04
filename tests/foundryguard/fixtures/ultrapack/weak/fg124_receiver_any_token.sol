// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract NftVault {
    mapping(uint256 => address) public depositor;

    function onERC721Received(address, address from, uint256 tokenId, bytes calldata) external returns (bytes4) {
        depositor[tokenId] = from;
        return this.onERC721Received.selector;
    }
}
