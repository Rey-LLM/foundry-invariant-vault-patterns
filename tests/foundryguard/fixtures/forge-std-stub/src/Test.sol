// SPDX-License-Identifier: MIT
// Minimal forge-std surface so generated suites can be compile-checked with solc in the unit tests.
pragma solidity >=0.8.0;
import { CommonBase } from "./Base.sol";
import { StdUtils } from "./StdUtils.sol";
abstract contract Test is CommonBase, StdUtils {
    struct FuzzSelector { address addr; bytes4[] selectors; }
    function targetContract(address) internal {}
    function targetSelector(FuzzSelector memory) internal {}
    function assertEq(uint256 a, uint256 b, string memory m) internal pure { require(a == b, m); }
    function assertEq(address a, address b, string memory m) internal pure { require(a == b, m); }
    function assertLe(uint256 a, uint256 b, string memory m) internal pure { require(a <= b, m); }
    function assertGe(uint256 a, uint256 b, string memory m) internal pure { require(a >= b, m); }
    function assertGt(uint256 a, uint256 b, string memory m) internal pure { require(a > b, m); }
}
