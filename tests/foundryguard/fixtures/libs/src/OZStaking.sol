// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice Staking pool on OpenZeppelin access control and reentrancy guard.
contract OZStaking is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable stakingToken;
    uint256 public totalStaked;
    mapping(address account => uint256) public stakedOf;
    mapping(address => mapping(uint256 => uint64)) public lockedUntil;
    uint256 internal constant MAX_LOCK = 52 weeks;

    constructor(IERC20 stakingToken_) Ownable(msg.sender) {
        stakingToken = stakingToken_;
    }

    function stake(uint256 amount) external nonReentrant {
        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        stakedOf[msg.sender] += amount;
        totalStaked += amount;
    }

    function unstake(uint256 amount) external nonReentrant {
        stakedOf[msg.sender] -= amount;
        totalStaked -= amount;
        stakingToken.safeTransfer(msg.sender, amount);
    }

    function sweep(address to) external payable onlyOwner {
        payable(to).transfer(address(this).balance);
    }
}
