// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TransientStaking} from "../../src/transient-vault/TransientStaking.sol";
import {
    TransientHandler,
    TransientStakingHarness,
    LeakyTransientStakingHarness,
    TransientStakingToken
} from "./TransientHandler.sol";

/// @notice Invariants for TransientStaking. EIP-1153 clears transient storage when the transaction
///         ends, so checking after the transaction proves nothing. The handler checks inside the
///         transaction instead, after each call and between the steps of a multicall.
contract TransientInvariantTest is Test {
    TransientStakingToken internal token;
    TransientStakingHarness internal vault;
    TransientHandler internal handler;

    function setUp() public {
        token = new TransientStakingToken();
        vault = new TransientStakingHarness(token);
        handler = new TransientHandler(vault, token);

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = TransientHandler.stake.selector;
        selectors[1] = TransientHandler.unstake.selector;
        selectors[2] = TransientHandler.claimPoints.selector;
        selectors[3] = TransientHandler.multicall.selector;
        selectors[4] = TransientHandler.warp.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice The lock and the entry amount are zero again whenever a call has returned.
    function invariant_transientSlotsClearedBetweenCalls() public view {
        assertEq(handler.ghostLeaks(), 0, "a transient slot was still set after a call returned");
    }

    function invariant_stakeSumMatchesTotal() public view {
        uint256 sum;
        for (uint256 i = 0; i < handler.actorCount(); i++) {
            sum += vault.stakedOf(handler.actors(i));
        }
        assertEq(sum, vault.totalStaked(), "stakedOf sum != totalStaked");
        assertEq(vault.totalStaked(), handler.ghostStaked() - handler.ghostUnstaked(), "totalStaked != ghost net stake");
    }

    function invariant_pointsSumMatchesTotal() public view {
        uint256 sum;
        for (uint256 i = 0; i < handler.actorCount(); i++) {
            sum += vault.pointsOf(handler.actors(i));
        }
        assertEq(sum, vault.totalPoints(), "pointsOf sum != totalPoints");
    }

    function invariant_tokenSolvency() public view {
        assertGe(token.balanceOf(address(vault)), vault.totalStaked(), "vault holds less than totalStaked");
    }
}

/// @notice Shows the planted bug in LeakyTransientStaking. A test function runs as one transaction, so
///         transient storage carries over from one call to the next, exactly as in a multicall.
contract LeakyTransientStakingTest is Test {
    uint256 internal constant AMOUNT = 1_000e18;
    uint256 internal constant BONUS = AMOUNT / 100;

    TransientStakingToken internal token;
    TransientStakingHarness internal fixedVault;
    LeakyTransientStakingHarness internal leakyVault;
    address internal user = address(0xA11CE);

    function setUp() public {
        token = new TransientStakingToken();
        fixedVault = new TransientStakingHarness(token);
        leakyVault = new LeakyTransientStakingHarness(token);
        token.mint(user, 10 * AMOUNT);
        vm.startPrank(user);
        token.approve(address(fixedVault), type(uint256).max);
        token.approve(address(leakyVault), type(uint256).max);
        vm.stopPrank();
    }

    function _stakeThenClaimTwice() internal pure returns (bytes[] memory calls) {
        calls = new bytes[](3);
        calls[0] = abi.encodeCall(TransientStaking.stake, (AMOUNT));
        calls[1] = abi.encodeCall(TransientStaking.claimPoints, ());
        calls[2] = abi.encodeCall(TransientStaking.claimPoints, ());
    }

    function test_fixedVaultPaysEntryBonusOnce() public {
        vm.prank(user);
        fixedVault.multicall(_stakeThenClaimTwice());
        assertEq(fixedVault.pointsOf(user), BONUS, "entry bonus paid more than once");
        bytes32 entrySlot = fixedVault.watchedSlots()[1];
        assertEq(fixedVault.transientSlot(entrySlot), 0, "entry slot left set");
    }

    function test_leakyVaultPaysEntryBonusOnEveryLaterCall() public {
        vm.prank(user);
        leakyVault.multicall(_stakeThenClaimTwice());
        assertEq(leakyVault.pointsOf(user), 3 * BONUS, "the leftover entry amount should be paid on every accrual");
        bytes32 entrySlot = leakyVault.watchedSlots()[1];
        assertEq(leakyVault.transientSlot(entrySlot), AMOUNT, "entry slot should still hold the stake amount");

        // The leak outlives the multicall: any later call in the same transaction is paid again.
        vm.prank(user);
        leakyVault.claimPoints();
        assertEq(leakyVault.pointsOf(user), 4 * BONUS, "a separate call in the same transaction is paid too");
    }
}
