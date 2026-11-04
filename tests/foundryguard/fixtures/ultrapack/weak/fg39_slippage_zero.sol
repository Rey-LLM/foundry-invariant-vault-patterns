// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IRouter {
    function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external returns (uint256[] memory);
}

contract Seller {
    IRouter public router;

    function sell(uint256 amountIn, address[] calldata path, uint256 deadline) external {
        require(amountIn > 0 && path.length > 1);
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);
    }
}
