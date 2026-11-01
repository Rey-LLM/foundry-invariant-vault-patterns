// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CommonBase} from "forge-std/Base.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {StakingPool} from "../../src/flashloan-reward/StakingPool.sol";

/// @notice Fuzz handler driving a fixed actor set through valid stakes,
///         unstakes, claims, forward time warps and same-block
///         stake/unstake cycles. Keeps independent ghost accounting of the
///         emission schedule.
contract RewardHandler is CommonBase, StdUtils {
    StakingPool public immutable pool;

    uint256 public constant MAX_STAKE = 1e24;
    uint256 public constant FLASH_AMOUNT = 1e27;

    address[] public actors;

    /// Rewards the schedule has emitted while at least one unit was staked.
    uint256 public ghostScheduled;
    /// Upper bound on rounding dust lost to floor division.
    uint256 public ghostDustBound;
    /// Sum of reward gained by same-block stake/unstake cycles (must stay 0).
    uint256 public ghostSameBlockGain;
    /// Snapshot of rewardPerToken taken at the end of the last action.
    uint256 public ghostLastRpt;
    uint256 public ghostLastRptTimestamp;

    constructor(StakingPool _pool) {
        pool = _pool;
        for (uint256 i = 0; i < 4; i++) {
            actors.push(address(uint160(0x1000 + i)));
        }
        _snapshot();
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function stake(uint256 actorSeed, uint256 amountSeed) external {
        address actor = _actor(actorSeed);
        uint256 amount = bound(amountSeed, 1, MAX_STAKE);
        _accrueDust();
        vm.prank(actor);
        pool.stake(amount);
        _snapshot();
    }

    function unstake(uint256 actorSeed, uint256 amountSeed) external {
        address actor = _actor(actorSeed);
        uint256 bal = pool.balanceOf(actor);
        if (bal == 0) return;
        uint256 amount = bound(amountSeed, 1, bal);
        _accrueDust();
        vm.prank(actor);
        pool.unstake(amount);
        _snapshot();
    }

    function claim(uint256 actorSeed) external {
        address actor = _actor(actorSeed);
        _accrueDust();
        vm.prank(actor);
        pool.claim();
        _snapshot();
    }

    /// @notice Stakes a very large amount and removes it in the same block,
    ///         recording any reward the round trip produced.
    function sameBlockCycle(uint256 actorSeed) external {
        address actor = _actor(actorSeed);
        _accrueDust();

        vm.prank(actor);
        pool.stake(FLASH_AMOUNT);
        uint256 earnedBefore = pool.earned(actor);

        vm.prank(actor);
        pool.unstake(FLASH_AMOUNT);
        uint256 afterCycle = pool.earned(actor);

        if (afterCycle > earnedBefore) ghostSameBlockGain += afterCycle - earnedBefore;
        _snapshot();
    }

    /// @notice Advances block time by 1 second up to 1 day.
    function warp(uint256 dtSeed) external {
        uint256 dt = bound(dtSeed, 1, 1 days);
        if (pool.totalStaked() > 0) ghostScheduled += pool.rewardRate() * dt;
        vm.warp(block.timestamp + dt);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, actors.length - 1)];
    }

    /// Each checkpoint can lose < 1 wei of rewardPerToken (worth at most
    /// totalStaked / PRECISION reward units in aggregate) plus < 1 wei for the
    /// checkpointed account.
    function _accrueDust() internal {
        ghostDustBound += pool.totalStaked() / pool.PRECISION() + 2;
    }

    function _snapshot() internal {
        ghostLastRpt = pool.rewardPerToken();
        ghostLastRptTimestamp = block.timestamp;
    }
}
