// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Batch {
    mapping(uint256 => mapping(address => uint256)) public balanceOf;

    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        require(to != address(0));
        require(ids.length == amounts.length, "length");
        for (uint256 i = 0; i < ids.length; i++) {
            balanceOf[ids[i]][to] += amounts[i];
        }
    }
}
