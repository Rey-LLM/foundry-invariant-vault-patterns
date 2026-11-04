// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract UUPSUpgradeable { function _authorizeUpgrade(address) internal virtual; function _disableInitializers() internal {} }

contract VaultV2 is UUPSUpgradeable {
    constructor() {
        _disableInitializers();
    }

    function _authorizeUpgrade(address) internal override {}
}
