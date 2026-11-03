// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Uniswap v4 style hook interface: the vault calls the registered hook around its flows
///         and requires the hook to answer with the function's own selector.
interface IVaultHooks {
    function beforeDeposit(address sender, uint256 assets) external returns (bytes4);
    function afterWithdraw(address sender, uint256 assets) external returns (bytes4);
}
