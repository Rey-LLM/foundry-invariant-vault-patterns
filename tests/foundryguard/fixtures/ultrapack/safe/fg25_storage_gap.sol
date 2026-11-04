// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

abstract contract Initializable {
    modifier onlyInitializing() {
        _;
    }
}

abstract contract FeeBase is Initializable {
    uint256 public fee;
    uint256[49] private __gap;

    function __FeeBase_init(uint256 f) internal onlyInitializing {
        fee = f;
    }
}
