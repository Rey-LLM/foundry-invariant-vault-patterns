// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Price of one whole unit of the vault token, 18 decimals.
interface IPriceOracle {
    function price() external view returns (uint256);
}
