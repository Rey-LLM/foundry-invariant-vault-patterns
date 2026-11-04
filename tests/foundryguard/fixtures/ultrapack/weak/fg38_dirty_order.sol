// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract Book {
    struct Order {
        address maker;
        uint256 amount;
        uint256 price;
    }

    IERC20 public token;

    function fillOrder(Order calldata order, uint256 amount) external {
        require(amount <= order.amount);
        require(token.transferFrom(order.maker, msg.sender, amount));
    }
}
