// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Proxy {
    address public implementation;
    address public admin;

    constructor(address impl) {
        require(impl != address(0));
        implementation = impl;
        admin = msg.sender;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
