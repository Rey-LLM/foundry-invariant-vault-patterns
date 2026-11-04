// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }

contract Sample {
    IPair public pair;

    function price() external view returns (uint256) {
        (uint112 a, uint112 b, ) = pair.getReserves();
        require(a > 0);
        return uint256(b) * 1e18 / a;
    }
}
