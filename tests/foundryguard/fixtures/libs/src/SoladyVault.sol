// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC4626 } from "solady/tokens/ERC4626.sol";
import { Ownable } from "solady/auth/Ownable.sol";

/// @notice ERC-4626 vault built on Solady. Every value flow is inherited.
contract SoladyVault is ERC4626, Ownable {
    address internal immutable _asset;

    constructor(address asset_) {
        _asset = asset_;
        _initializeOwner(msg.sender);
    }

    function asset() public view override returns (address) {
        return _asset;
    }

    function name() public pure override returns (string memory) {
        return "Solady Vault";
    }

    function symbol() public pure override returns (string memory) {
        return "sVLT";
    }
}
