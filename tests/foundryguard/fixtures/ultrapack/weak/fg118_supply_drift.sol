// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract ERC1155 {
    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal virtual;
    function _burn(address from, uint256 id, uint256 amount) internal virtual;
}

contract Items is ERC1155 {
    mapping(uint256 => uint256) public totalSupply;

    function mint(uint256 id, uint256 amount) external {
        require(amount > 0);
        totalSupply[id] += amount;
        _mint(msg.sender, id, amount, "");
    }

    function burn(uint256 id, uint256 amount) external {
        require(amount > 0);
        _burn(msg.sender, id, amount);
    }
}
