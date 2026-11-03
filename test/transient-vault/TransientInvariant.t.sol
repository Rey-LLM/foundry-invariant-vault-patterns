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

/// @notice Shows the planted bug in LeakyTransientStaking. Forge resets transient storage between the
///         test's own top-level calls, so every step, including the slot read, runs inside one multicall.
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

    /// @dev The last step reads the entry slot from inside the same multicall, so the read happens in the
    ///      transaction that ran the stake, which is where the leftover value lives.
    function _stakeClaimClaimRead(bytes32 entrySlot) internal pure returns (bytes[] memory calls) {
        calls = new bytes[](4);
        calls[0] = abi.encodeCall(TransientStaking.stake, (AMOUNT));
        calls[1] = abi.encodeCall(TransientStaking.claimPoints, ());
        calls[2] = abi.encodeCall(TransientStaking.claimPoints, ());
        calls[3] = abi.encodeCall(TransientStakingHarness.transientSlot, (entrySlot));
    }

    function test_fixedVaultPaysEntryBonusOnce() public {
        bytes32 entrySlot = fixedVault.watchedSlots()[1];
        vm.prank(user);
        bytes[] memory results = fixedVault.multicall(_stakeClaimClaimRead(entrySlot));
        assertEq(fixedVault.pointsOf(user), BONUS, "entry bonus paid more than once");
        assertEq(abi.decode(results[3], (uint256)), 0, "entry slot left set after stake");
    }

    function test_leakyVaultPaysEntryBonusOnEveryLaterCall() public {
        bytes32 entrySlot = leakyVault.watchedSlots()[1];
        vm.prank(user);
        bytes[] memory results = leakyVault.multicall(_stakeClaimClaimRead(entrySlot));
        assertEq(leakyVault.pointsOf(user), 3 * BONUS, "the leftover entry amount should be paid on every accrual");
        assertEq(abi.decode(results[3], (uint256)), AMOUNT, "entry slot should still hold the stake amount");
    }
}
