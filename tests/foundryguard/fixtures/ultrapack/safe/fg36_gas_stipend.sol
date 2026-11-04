// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner = msg.sender;

    function pay(address payable to) external {
        require(msg.sender == owner);
        (bool ok, ) = to.call{value: 1 ether}("");
        require(ok);
    }
}
