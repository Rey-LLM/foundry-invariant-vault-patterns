// SPDX-License-Identifier: MIT
// Minimal forge-std surface so generated suites can be compile-checked with solc in the unit tests.
pragma solidity >=0.8.0;
import { Vm } from "./Vm.sol";
abstract contract CommonBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}
