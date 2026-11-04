// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract UUPSUpgradeable { function _authorizeUpgrade(address) internal virtual; function _disableInitializers() internal {} }

contract VaultV2 is UUPSUpgradeable {
    address public owner = msg.sender;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
