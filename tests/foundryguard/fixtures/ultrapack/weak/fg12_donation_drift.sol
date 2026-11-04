// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Sample {
    IERC20 public token;

    function assets() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
