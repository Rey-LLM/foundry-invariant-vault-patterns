// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface INFT { function safeTransferFrom(address from, address to, uint256 id) external; }

contract NftStaking {
    INFT public nft;
    mapping(uint256 => address) public stakerOf;

    function stake(uint256 tokenId) external {
        stakerOf[tokenId] = msg.sender;
        nft.safeTransferFrom(msg.sender, address(this), tokenId);
    }

    function unstake(uint256 tokenId) external {
        require(stakerOf[tokenId] == msg.sender, "not staker");
        nft.safeTransferFrom(address(this), msg.sender, tokenId);
    }
}
