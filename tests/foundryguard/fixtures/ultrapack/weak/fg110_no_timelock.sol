// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Fees {
    address public owner = msg.sender;
    uint256 public withdrawFee;

    function setWithdrawFee(uint256 newFee) external {
        require(msg.sender == owner);
        withdrawFee = newFee;
    }
}
