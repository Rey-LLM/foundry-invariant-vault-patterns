// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Fees {
    address public owner = msg.sender;
    uint256 public withdrawFee;
    uint256 public constant MAX_FEE = 500;

    function setWithdrawFee(uint256 newFee) external {
        require(msg.sender == owner);
        require(newFee <= MAX_FEE, "cap");
        withdrawFee = newFee;
    }
}
