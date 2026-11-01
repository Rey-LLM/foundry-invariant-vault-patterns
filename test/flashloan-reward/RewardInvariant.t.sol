// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StakingPool} from "../../src/flashloan-reward/StakingPool.sol";
import {RewardHandler} from "./RewardHandler.sol";

contract RewardInvariantTest is Test {
    StakingPool internal pool;
    RewardHandler internal handler;

    function setUp() public {
        vm.warp(1_000_000);
        pool = new StakingPool(1e18);
        handler = new RewardHandler(pool);

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = RewardHandler.stake.selector;
        selectors[1] = RewardHandler.unstake.selector;
        selectors[2] = RewardHandler.claim.selector;
        selectors[3] = RewardHandler.sameBlockCycle.selector;
        selectors[4] = RewardHandler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function _distributed() internal view returns (uint256 total) {
        total = pool.totalClaimed();
        uint256 n = handler.actorCount();
        for (uint256 i = 0; i < n; i++) {
            total += pool.earned(handler.actors(i));
        }
    }

    /// Claimed plus pending rewards never exceed the emission schedule.
    function invariant_distributedNotAboveSchedule() public view {
        assertLe(_distributed(), handler.ghostScheduled());
    }

    /// Claimed plus pending rewards match the schedule up to bounded
    /// floor-division dust.
    function invariant_distributedMatchesSchedule() public view {
        uint256 dust = handler.ghostDustBound() + pool.totalStaked() / pool.PRECISION() + 1
            + handler.actorCount();
        assertApproxEqAbs(_distributed(), handler.ghostScheduled(), dust);
    }

    /// Same-block stake/unstake round trips never produce reward.
    function invariant_noSameBlockRewardGain() public view {
        assertEq(handler.ghostSameBlockGain(), 0);
    }

    /// rewardPerToken cannot move unless block time advances.
    function invariant_rewardPerTokenStableWithinBlock() public view {
        if (block.timestamp == handler.ghostLastRptTimestamp()) {
            assertEq(pool.rewardPerToken(), handler.ghostLastRpt());
        } else {
            assertGe(pool.rewardPerToken(), handler.ghostLastRpt());
        }
    }

    /// Accounting of stake balances is conserved.
    function invariant_totalStakedEqualsSumOfBalances() public view {
        uint256 sum;
        uint256 n = handler.actorCount();
        for (uint256 i = 0; i < n; i++) {
            sum += pool.balanceOf(handler.actors(i));
        }
        assertEq(sum, pool.totalStaked());
    }
}
