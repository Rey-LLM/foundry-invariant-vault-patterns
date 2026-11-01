// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { IERC4626 } from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import { Vm } from "forge-std/Vm.sol";
import { MockAsset } from "./MockERC4626.sol";

/// @notice Bounded state transitions and sticky observations for a closed four-actor system.
contract Handler {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 public constant MAX_ACTION_ASSETS = 1e24;
    uint256 public constant ACTOR_COUNT = 4;

    IERC4626 public immutable vault;
    MockAsset public immutable asset;
    address[4] public actors;

    uint256 public depositCalls;
    uint256 public withdrawCalls;
    uint256 public donationCalls;
    uint256 public skippedWithdrawals;
    uint256 public rejectedDeposits;
    uint256 public ghostDepositedAssets;
    uint256 public ghostWithdrawnAssets;
    uint256 public ghostDonatedAssets;
    uint256 public zeroShareDeposits;
    uint256 public underBurnWithdrawals;
    uint256 public transitionDefects;

    error AssetMismatch();
    error UnexpectedDepositRevert(bytes reason);
    error TokenOperationFailed();

    constructor(IERC4626 vault_, MockAsset asset_) {
        if (vault_.asset() != address(asset_)) revert AssetMismatch();
        vault = vault_;
        asset = asset_;
        for (uint256 i; i < ACTOR_COUNT; ++i) {
            address actor = address(uint160(0x1000 + i));
            actors[i] = actor;
            VM.prank(actor);
            if (!asset_.approve(address(vault_), type(uint256).max)) revert TokenOperationFailed();
        }
    }

    function deposit(uint256 actorSeed, uint256 rawAssets) external {
        address actor = actors[actorSeed % ACTOR_COUNT];
        uint256 assets = 1 + rawAssets % MAX_ACTION_ASSETS;
        asset.mint(actor, assets);
        uint256 assetsBefore = vault.totalAssets();
        uint256 sharesBefore = vault.balanceOf(actor);
        uint256 walletBefore = asset.balanceOf(actor);
        uint256 supplyBefore = vault.totalSupply();
        uint256 preview = vault.previewDeposit(assets);

        VM.prank(actor);
        try vault.deposit(assets, actor) returns (uint256 shares) {
            ++depositCalls;
            ghostDepositedAssets += assets;
            if (shares == 0) ++zeroShareDeposits;
            if (
                shares < preview || vault.balanceOf(actor) != sharesBefore + shares
                    || vault.totalSupply() != supplyBefore + shares || vault.totalAssets() != assetsBefore + assets
                    || asset.balanceOf(actor) + assets != walletBefore
            ) ++transitionDefects;
        } catch (bytes memory reason) {
            if (preview != 0) revert UnexpectedDepositRevert(reason);
            ++rejectedDeposits;
            if (
                vault.totalAssets() != assetsBefore || vault.balanceOf(actor) != sharesBefore
                    || vault.totalSupply() != supplyBefore || asset.balanceOf(actor) != walletBefore
            ) ++transitionDefects;
        }
    }

    function withdraw(uint256 actorSeed, uint256 rawAssets) external {
        address actor = actors[actorSeed % ACTOR_COUNT];
        uint256 available = vault.maxWithdraw(actor);
        if (available == 0) {
            ++skippedWithdrawals;
            return;
        }
        uint256 limit = available < MAX_ACTION_ASSETS ? available : MAX_ACTION_ASSETS;
        uint256 assets = 1 + rawAssets % limit;
        uint256 assetsBefore = vault.totalAssets();
        uint256 supplyBefore = vault.totalSupply();
        uint256 sharesBefore = vault.balanceOf(actor);
        uint256 walletBefore = asset.balanceOf(actor);
        uint256 preview = vault.previewWithdraw(assets);

        VM.prank(actor);
        uint256 burned = vault.withdraw(assets, actor, actor);
        ++withdrawCalls;
        ghostWithdrawnAssets += assets;

        // Independent rational-price check, without calling a vault conversion function.
        if (burned * assetsBefore < assets * supplyBefore) ++underBurnWithdrawals;
        if (
            burned > preview || vault.balanceOf(actor) + burned != sharesBefore
                || vault.totalSupply() + burned != supplyBefore || vault.totalAssets() + assets != assetsBefore
                || asset.balanceOf(actor) != walletBefore + assets
        ) ++transitionDefects;
    }

    function donate(uint256 actorSeed, uint256 rawAssets) external {
        address actor = actors[actorSeed % ACTOR_COUNT];
        uint256 assets = 1 + rawAssets % MAX_ACTION_ASSETS;
        asset.mint(actor, assets);
        uint256 supplyBefore = vault.totalSupply();
        uint256 assetsBefore = vault.totalAssets();
        VM.prank(actor);
        if (!asset.transfer(address(vault), assets)) revert TokenOperationFailed();
        ++donationCalls;
        ghostDonatedAssets += assets;
        if (vault.totalSupply() != supplyBefore || vault.totalAssets() != assetsBefore + assets) ++transitionDefects;
    }
}
