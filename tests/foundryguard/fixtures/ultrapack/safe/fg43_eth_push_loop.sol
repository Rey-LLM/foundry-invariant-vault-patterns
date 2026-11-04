// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Lottery {
    address[10] public winners;
    uint256 public round;
    mapping(address => uint256) public pending;

    function payout() external {
        round += 1;
        for (uint256 i = 0; i < 10; i++) {
            pending[winners[i]] += 1 ether;
        }
    }
}
