// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }

contract Vault {
    address public owner = msg.sender;
    IERC20 public stakingToken;

    function rescueTokens(address token, address to, uint256 amount) external {
        require(msg.sender == owner);
        require(token != address(stakingToken), "stake");
        require(IERC20(token).transfer(to, amount));
    }
}
