// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Router {
    address public owner = msg.sender;

    function exec(address target, bytes calldata data) external {
        require(target != address(0));
        (bool ok, ) = target.call(data);
        require(ok);
    }
}
