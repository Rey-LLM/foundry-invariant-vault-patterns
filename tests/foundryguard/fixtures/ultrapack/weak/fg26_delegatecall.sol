// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Sample {
    address public owner = msg.sender;

    function run(address impl, bytes calldata d) external {
        require(msg.sender == owner);
        (bool ok, ) = impl.delegatecall(d);
        require(ok);
    }
}
