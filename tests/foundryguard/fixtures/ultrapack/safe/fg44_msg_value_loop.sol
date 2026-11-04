// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Shop {
    uint256 public price = 1 ether;
    uint256 public minted;

    function buyMany(uint256 n) external payable {
        require(msg.value == price * n);
        for (uint256 i = 0; i < n; i++) {
            minted += 1;
        }
    }
}
