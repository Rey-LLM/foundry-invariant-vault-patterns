// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner;

    function initialize(address o) external {
        require(o != address(0));
        owner = o;
    }
}
