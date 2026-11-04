// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract NftVault {
    address public immutable nft;
    mapping(uint256 => address) public depositor;

    constructor(address nft_) { require(nft_ != address(0)); nft = nft_; }

    function onERC721Received(address, address from, uint256 tokenId, bytes calldata) external returns (bytes4) {
        require(msg.sender == nft, "wrong collection");
        depositor[tokenId] = from;
        return this.onERC721Received.selector;
    }
}
