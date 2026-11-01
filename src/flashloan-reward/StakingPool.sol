// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title StakingPool
/// @notice Minimal multi-asset-agnostic staking vault using standard
///         time-weighted reward-per-token accounting. Rewards accrue strictly
///         as a function of elapsed time, so capital that enters and leaves
///         within the same block (e.g. flash-loaned liquidity) earns nothing.
/// @dev Reward balances are internal accounting only; no token transfers are
///      performed so the model stays self-contained for invariant testing.
contract StakingPool {
    uint256 public constant PRECISION = 1e18;

    /// @notice Reward units emitted per second across all stakers.
    uint256 public immutable rewardRate;

    uint256 public totalStaked;
    uint256 public rewardPerTokenStored;
    uint256 public lastUpdateTime;
    uint256 public totalClaimed;

    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public claimed;

    error ZeroAmount();
    error InsufficientStake();

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);

    constructor(uint256 _rewardRate) {
        rewardRate = _rewardRate;
        lastUpdateTime = block.timestamp;
    }

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    /// @notice Accumulated reward per staked unit, scaled by PRECISION.
    /// @dev Depends only on elapsed time since the last checkpoint. With zero
    ///      elapsed time (same block) the value cannot move, regardless of how
    ///      much balance is added or removed.
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) return rewardPerTokenStored;
        uint256 elapsed = block.timestamp - lastUpdateTime;
        return rewardPerTokenStored + (elapsed * rewardRate * PRECISION) / totalStaked;
    }

    function earned(address account) public view returns (uint256) {
        return rewards[account]
            + (balanceOf[account] * (rewardPerToken() - userRewardPerTokenPaid[account])) / PRECISION;
    }

    function stake(uint256 amount) external updateReward(msg.sender) {
        if (amount == 0) revert ZeroAmount();
        totalStaked += amount;
        balanceOf[msg.sender] += amount;
        emit Staked(msg.sender, amount);
    }

    function unstake(uint256 amount) external updateReward(msg.sender) {
        if (amount == 0) revert ZeroAmount();
        if (amount > balanceOf[msg.sender]) revert InsufficientStake();
        totalStaked -= amount;
        balanceOf[msg.sender] -= amount;
        emit Unstaked(msg.sender, amount);
    }

    function claim() external updateReward(msg.sender) returns (uint256 amount) {
        amount = rewards[msg.sender];
        if (amount == 0) return 0;
        rewards[msg.sender] = 0;
        claimed[msg.sender] += amount;
        totalClaimed += amount;
        emit RewardClaimed(msg.sender, amount);
    }
}
