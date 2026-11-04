// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract LotteryVault {
    IERC20 public immutable token;
    address public treasury;
    address[] public players;
    mapping(address => uint256) public stakes;

    constructor(IERC20 token_) {
        token = token_;
    }

    function setTreasury(address newTreasury) external {
        require(tx.origin == treasury, "auth");
        treasury = newTreasury;
    }

    function enterFor(address from, uint256 amount) external {
        require(amount > 0, "zero");
        token.transferFrom(from, address(this), amount);
        stakes[from] += amount;
        players.push(from);
    }

    function draw() external {
        uint256 pick = block.timestamp % players.length;
        uint256 total;
        for (uint256 i = 0; i < players.length; i++) {
            total += stakes[players[i]];
        }
        uint256 prize = total / 100 * 95;
        token.transfer(players[pick], prize);
    }

    function sweep(address payable to) external {
        require(msg.sender == treasury, "auth");
        to.call{value: address(this).balance}("");
    }
}
