// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

library OracleLib { function consult(address, uint32) internal pure returns (int24) { return 0; } }

contract Sample {
    uint32 public constant TWAP_PERIOD = 30 minutes;
    address public pool;

    function price() external view returns (int24) {
        return OracleLib.consult(pool, TWAP_PERIOD);
    }
}
