// SPDX-License-Identifier: MIT
// Minimal forge-std surface so generated suites can be compile-checked with solc in the unit tests.
pragma solidity >=0.8.0;
abstract contract StdUtils {
    function bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        require(min <= max);
        return min + x % (max - min + 1);
    }
}
