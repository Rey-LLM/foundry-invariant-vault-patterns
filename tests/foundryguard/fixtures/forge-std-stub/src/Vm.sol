// SPDX-License-Identifier: MIT
// Minimal forge-std surface so generated suites can be compile-checked with solc in the unit tests.
pragma solidity >=0.8.0;
interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function deal(address, uint256) external;
    function warp(uint256) external;
    function roll(uint256) external;
}
