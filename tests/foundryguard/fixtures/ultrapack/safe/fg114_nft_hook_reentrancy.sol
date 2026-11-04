// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract ERC721 {
    function _mint(address to, uint256 id) internal virtual;
    function _safeMint(address to, uint256 id) internal virtual;
}

contract Drop is ERC721 {
    uint256 public next;
    mapping(address => uint256) public minted;

    function mint() external {
        require(minted[msg.sender] < 2, "limit");
        minted[msg.sender] += 1;
        uint256 id = next;
        next = id + 1;
        _safeMint(msg.sender, id);
    }
}
