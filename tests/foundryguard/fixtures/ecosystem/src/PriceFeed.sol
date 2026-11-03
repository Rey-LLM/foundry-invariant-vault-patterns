// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IPriceOracle } from "./IPriceOracle.sol";

/// @title PriceFeed
/// @notice Owner-pushed price, the shape of most keeper-updated feeds. Both vaults read it.
contract PriceFeed is IPriceOracle {
    address public immutable owner;
    uint256 public override price;
    uint256 public updatedAt;

    error NotOwner();
    error ZeroPrice();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(uint256 initialPrice) {
        if (initialPrice == 0) revert ZeroPrice();
        owner = msg.sender;
        price = initialPrice;
        updatedAt = block.timestamp;
    }

    function setPrice(uint256 newPrice) external onlyOwner {
        if (newPrice == 0) revert ZeroPrice();
        price = newPrice;
        updatedAt = block.timestamp;
    }
}
