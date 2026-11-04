// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    mapping(address => uint256) public bal;

    function withdraw() external {
        uint256 a = bal[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
