// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract Initializable { modifier initializer() { _; } function _disableInitializers() internal {} }

contract VaultV1 is Initializable {
    address public owner;

    constructor() {
        _disableInitializers();
    }

    function initialize(address o) external initializer {
        require(o != address(0));
        owner = o;
    }
}
