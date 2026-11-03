// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC20 as SoladyERC20 } from "solady/tokens/ERC20.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Two tokens whose parents are both called ERC20: the AST tells them apart.
contract SoladyShare is SoladyERC20 {
    function name() public pure override returns (string memory) {
        return "Solady Share";
    }

    function symbol() public pure override returns (string memory) {
        return "sSHR";
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract OZShare is ERC20("OZ Share", "oSHR") {
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
