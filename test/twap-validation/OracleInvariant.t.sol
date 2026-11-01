// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PriceOracleModel} from "../../src/twap-validation/PriceOracleModel.sol";
import {OracleHandler} from "./OracleHandler.sol";

contract OracleInvariantTest is Test {
    PriceOracleModel internal model;
    OracleHandler internal handler;

    function setUp() public {
        vm.warp(1_000_000);
        model = new PriceOracleModel(1e18);
        handler = new OracleHandler(model);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = OracleHandler.updatePrice.selector;
        selectors[1] = OracleHandler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// Spot price never leaves the configured hard bounds.
    function invariant_spotWithinBounds() public view {
        uint256 p = model.spotPrice();
        assertGe(p, model.MIN_PRICE());
        assertLe(p, model.MAX_PRICE());
    }

    /// The model's cumulative matches independently computed ghost accounting.
    function invariant_cumulativeMatchesGhost() public view {
        assertEq(model.currentCumulative(), handler.ghostCumulative());
    }

    /// Full-history TWAP always lies within [min, max] of the prices seen.
    function invariant_twapBoundedByObservedRange() public view {
        uint256 elapsed = block.timestamp - model.firstTimestamp();
        if (elapsed == 0) return;
        uint256 twap = model.consult(elapsed);
        assertGe(twap, handler.ghostMinPrice(), "TWAP below observed min");
        assertLe(twap, handler.ghostMaxPrice(), "TWAP above observed max");
    }

    /// Short-window TWAP stays within the max cumulative drift of spot.
    /// No single update can move price by more than MAX_DEVIATION_BPS, and
    /// a 1-second window can include at most the pre-update price.
    function invariant_shortWindowDriftBounded() public view {
        if (block.timestamp - model.firstTimestamp() < 1) return;
        uint256 twap = model.consult(1);
        uint256 spot = model.spotPrice();
        uint256 diff = twap > spot ? twap - spot : spot - twap;
        // |twap - spot| <= deviation measured against the previous price,
        // which is at most spot * MAX_DEV / (BPS - MAX_DEV); allow +1 for rounding.
        uint256 tol = (spot * model.MAX_DEVIATION_BPS()) / (model.BPS() - model.MAX_DEVIATION_BPS()) + 1;
        assertLe(diff, tol, "short-window drift exceeded tolerance");
    }

    /// No accepted update exceeded the per-update deviation cap.
    function invariant_deviationCapRespected() public view {
        assertLe(handler.ghostMaxDeviationBps(), model.MAX_DEVIATION_BPS());
    }

    /// Observation timestamps are strictly increasing.
    function invariant_observationsMonotonic() public view {
        uint256 n = model.observationCount();
        for (uint256 i = 1; i < n; i++) {
            assertGt(model.observation(i).timestamp, model.observation(i - 1).timestamp);
        }
    }
}
