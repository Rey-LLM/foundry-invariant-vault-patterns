// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC4626 } from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import { IERC4626 } from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import { MockAsset, MockERC4626, FloorWithdrawERC4626 } from "../../src/erc4626-inflation/MockERC4626.sol";
import { Handler } from "../../src/erc4626-inflation/Handler.sol";

contract ProtectedVault is ERC4626 {
    error ZeroShares();

    constructor(IERC20 asset_) ERC20("Protected Vault Share", "pASSET") ERC4626(asset_) { }

    function _decimalsOffset() internal pure override returns (uint8) {
        return 6;
    }

    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
        if (assets != 0 && shares == 0) revert ZeroShares();
        super._deposit(caller, receiver, assets, shares);
    }
}

abstract contract VaultInvariantBase is StdInvariant, Test {
    MockAsset internal asset;
    IERC4626 internal vault;
    Handler internal handler;

    function _deployVault() internal virtual returns (IERC4626) {
        return IERC4626(address(new MockERC4626(asset)));
    }

    function setUp() public virtual {
        asset = new MockAsset();
        vault = _deployVault();
        handler = new Handler(vault, asset);
        handler.deposit(0, 0);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = Handler.deposit.selector;
        selectors[1] = Handler.withdraw.selector;
        selectors[2] = Handler.donate.selector;
        targetSelector(FuzzSelector({ addr: address(handler), selectors: selectors }));
    }

    function invariant_assetConservation() public view {
        assertEq(
            vault.totalAssets() + handler.ghostWithdrawnAssets(),
            handler.ghostDepositedAssets() + handler.ghostDonatedAssets(),
            "vault flow ledger does not conserve assets"
        );
        uint256 assetsHeld = vault.totalAssets();
        for (uint256 i; i < handler.ACTOR_COUNT(); ++i) {
            assetsHeld += asset.balanceOf(handler.actors(i));
        }
        assertEq(assetsHeld, asset.totalSupply(), "closed-system asset conservation");
    }

    function invariant_shareConservation() public view {
        uint256 sharesHeld;
        for (uint256 i; i < handler.ACTOR_COUNT(); ++i) {
            sharesHeld += vault.balanceOf(handler.actors(i));
        }
        assertEq(sharesHeld, vault.totalSupply(), "share supply does not match actor balances");
    }

    function invariant_transitionsMatchPreviewsAndBalances() public view {
        assertEq(handler.transitionDefects(), 0, "preview or balance transition defect");
    }

    function invariant_withdrawalsBurnEnoughShares() public view {
        assertEq(handler.underBurnWithdrawals(), 0, "withdrawal rounded shares down");
    }
}

/// @notice Expected to fail: the fuzzer discovers a successful deposit with zero shares.
contract InflationInvariant is VaultInvariantBase {
    function invariant_positiveDepositsReceiveShares() public view {
        assertEq(handler.zeroShareDeposits(), 0, "positive deposit minted zero shares");
    }
}

contract AccountingInvariant is VaultInvariantBase { }

/// @notice Expected to fail independently of the zero-share deposit property.
contract WithdrawalRoundingInvariant is VaultInvariantBase {
    function _deployVault() internal override returns (IERC4626) {
        return IERC4626(address(new FloorWithdrawERC4626(asset)));
    }
}

contract ProtectedInvariant is VaultInvariantBase {
    function _deployVault() internal override returns (IERC4626) {
        return IERC4626(address(new ProtectedVault(asset)));
    }

    function invariant_positiveDepositsReceiveShares() public view {
        assertEq(handler.zeroShareDeposits(), 0, "positive deposit minted zero shares");
    }
}

contract InflationMatrixTest is Test {
    MockAsset internal asset;
    MockERC4626 internal vault;
    address internal attacker = address(0xA11CE);
    address internal victim = address(0xB0B);

    function setUp() public {
        asset = new MockAsset();
        vault = new MockERC4626(asset);
    }

    function _deposit(IERC4626 target, address actor, uint256 assets) internal returns (uint256 shares) {
        asset.mint(actor, assets);
        vm.startPrank(actor);
        asset.approve(address(target), assets);
        shares = target.deposit(assets, actor);
        vm.stopPrank();
    }

    function _donate(IERC4626 target, uint256 assets) internal {
        asset.mint(attacker, assets);
        vm.prank(attacker);
        asset.transfer(address(target), assets);
    }

    function test_normalDepositAndWithdraw() public {
        assertEq(_deposit(vault, victim, 100), 100);
        vm.prank(victim);
        assertEq(vault.withdraw(40, victim, victim), 40);
        assertEq(vault.balanceOf(victim), 60);
        assertEq(asset.balanceOf(victim), 40);
    }

    function testFuzz_inflationStealsEntireVictimDeposit(uint96 rawVictimAssets) public {
        uint256 victimAssets = bound(uint256(rawVictimAssets), 1, 1e24);
        _deposit(vault, attacker, 1);
        _donate(vault, victimAssets);
        assertEq(vault.previewDeposit(victimAssets), 0);
        assertEq(_deposit(vault, victim, victimAssets), 0);
        vm.prank(attacker);
        uint256 recovered = vault.redeem(1, attacker, attacker);
        assertEq(recovered, 1 + 2 * victimAssets);
        assertEq(recovered - (1 + victimAssets), victimAssets);
        assertEq(asset.balanceOf(victim), 0);
        assertEq(vault.totalAssets(), 0);
    }

    function test_partialShareRoundingLoss() public {
        _deposit(vault, attacker, 2);
        _donate(vault, 3);
        assertEq(_deposit(vault, victim, 4), 1);
        vm.prank(victim);
        assertEq(vault.redeem(1, victim, victim), 3);
        vm.prank(attacker);
        assertEq(vault.redeem(2, attacker, attacker), 6);
    }

    function test_donationBeforeFirstDepositIsCaptured() public {
        _donate(vault, 100);
        assertEq(_deposit(vault, victim, 1), 1);
        vm.prank(victim);
        assertEq(vault.redeem(1, victim, victim), 101);
    }

    function test_withdrawRoundsUp() public {
        _deposit(vault, attacker, 1);
        _deposit(vault, victim, 1);
        _donate(vault, 1);
        assertEq(vault.previewWithdraw(1), 1);
        vm.prank(victim);
        assertEq(vault.withdraw(1, victim, victim), 1);
    }

    function test_floorWithdrawalTransfersAssetsWithoutBurningShares() public {
        FloorWithdrawERC4626 broken = new FloorWithdrawERC4626(asset);
        _deposit(broken, attacker, 1);
        _deposit(broken, victim, 1);
        _donate(broken, 1);
        assertEq(broken.previewWithdraw(1), 0);
        vm.prank(attacker);
        assertEq(broken.withdraw(1, attacker, attacker), 0);
        assertEq(broken.balanceOf(attacker), 1);
        assertEq(asset.balanceOf(attacker), 1);
        assertEq(broken.convertToAssets(broken.balanceOf(victim)), 1);
    }

    function test_handlerRecordsBothDefects() public {
        FloorWithdrawERC4626 broken = new FloorWithdrawERC4626(asset);
        Handler recorder = new Handler(broken, asset);
        recorder.deposit(0, 0);
        recorder.donate(0, 99);
        recorder.deposit(1, 49);
        recorder.withdraw(0, 0);
        assertEq(recorder.zeroShareDeposits(), 1);
        assertEq(recorder.underBurnWithdrawals(), 1);
        assertEq(recorder.transitionDefects(), 0);
    }

    function test_handlerCoversAllActionsAndEmptyWithdrawal() public {
        Handler recorder = new Handler(vault, asset);
        recorder.withdraw(0, 0);
        recorder.deposit(0, 99);
        recorder.donate(1, 9);
        recorder.withdraw(0, 9);
        assertEq(recorder.skippedWithdrawals(), 1);
        assertEq(recorder.depositCalls(), 1);
        assertEq(recorder.donationCalls(), 1);
        assertEq(recorder.withdrawCalls(), 1);
        assertEq(recorder.underBurnWithdrawals(), 0);
        assertEq(recorder.transitionDefects(), 0);
    }

    function test_protectedVaultPreventsSeedAttackProfit() public {
        ProtectedVault protected = new ProtectedVault(asset);
        uint256 attackerShares = _deposit(protected, attacker, 1);
        _donate(protected, 100);
        assertGt(_deposit(protected, victim, 100), 0);
        vm.prank(attacker);
        uint256 recovered = protected.redeem(attackerShares, attacker, attacker);
        assertLe(recovered, 101);
    }

    function test_protectedVaultRejectsZeroShareDeposit() public {
        ProtectedVault protected = new ProtectedVault(asset);
        _deposit(protected, attacker, 1);
        _donate(protected, 2_000_000);
        asset.mint(victim, 1);
        vm.startPrank(victim);
        asset.approve(address(protected), 1);
        vm.expectRevert(ProtectedVault.ZeroShares.selector);
        protected.deposit(1, victim);
        vm.stopPrank();
        assertEq(asset.balanceOf(victim), 1);
    }

    function test_handlerRecordsProtectedDepositRejection() public {
        ProtectedVault protected = new ProtectedVault(asset);
        Handler recorder = new Handler(protected, asset);
        recorder.deposit(0, 0);
        recorder.donate(0, 1_999_999);
        recorder.deposit(1, 0);
        assertEq(recorder.rejectedDeposits(), 1);
        assertEq(recorder.depositCalls(), 1);
        assertEq(recorder.zeroShareDeposits(), 0);
        assertEq(recorder.transitionDefects(), 0);
        assertEq(asset.balanceOf(recorder.actors(1)), 1);
    }

    function test_withdrawRequiresShareAllowanceForAnotherOwner() public {
        _deposit(vault, victim, 10);
        vm.prank(attacker);
        vm.expectRevert();
        vault.withdraw(1, attacker, victim);
        assertEq(vault.balanceOf(victim), 10);
    }

    function test_mintRoundsUpAndRedeemRoundsDown() public {
        _deposit(vault, attacker, 2);
        _donate(vault, 1);
        assertEq(vault.previewMint(1), 2);
        assertEq(vault.previewRedeem(1), 1);
        asset.mint(victim, 2);
        vm.startPrank(victim);
        asset.approve(address(vault), 2);
        assertEq(vault.mint(1, victim), 2);
        assertEq(vault.redeem(1, victim, victim), 1);
        vm.stopPrank();
    }
}
