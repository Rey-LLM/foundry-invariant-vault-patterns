// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract SafeLotteryVault {
    error ZeroAddress();
    error NotTreasury();
    error TransferFailed();

    IERC20 public immutable token;
    address public treasury;
    mapping(address => uint256) public stakes;
    uint256 public totalStaked;

    constructor(IERC20 token_, address treasury_) {
        if (address(token_) == address(0) || treasury_ == address(0)) revert ZeroAddress();
        token = token_;
        treasury = treasury_;
    }

    function setTreasury(address newTreasury) external {
        if (msg.sender != treasury) revert NotTreasury();
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = newTreasury;
    }

    function enter(uint256 amount) external {
        require(amount > 0, "zero");
        stakes[msg.sender] += amount;
        totalStaked += amount;
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
    }

    function payout(address winner, uint256 bps) external {
        if (msg.sender != treasury) revert NotTreasury();
        if (winner == address(0)) revert ZeroAddress();
        require(bps <= 10_000, "bps");
        uint256 prize = totalStaked * bps / 10_000;
        totalStaked -= prize;
        require(token.transfer(winner, prize), "transfer");
    }
}
