// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract ERC721 {
    function _mint(address to, uint256 id) internal virtual;
    function _safeMint(address to, uint256 id) internal virtual;
}

contract Drop is ERC721 {
    uint256 public next;

    function mintTo(address to) external {
        require(to != address(0));
        _mint(to, next++);
    }
}
