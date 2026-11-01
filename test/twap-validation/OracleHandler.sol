// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CommonBase} from "forge-std/Base.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {PriceOracleModel} from "../../src/twap-validation/PriceOracleModel.sol";

/// @notice Fuzz handler that only issues valid actions: bounded price moves
///         and forward time jumps. It keeps independent ghost accounting.
contract OracleHandler is CommonBase, StdUtils {
    PriceOracleModel public immutable model;

    uint256 public ghostCumulative;
    uint256 public ghostMinPrice;
    uint256 public ghostMaxPrice;
    uint256 public ghostMaxDeviationBps;

    constructor(PriceOracleModel _model) {
        model = _model;
        uint256 p = _model.spotPrice();
        ghostMinPrice = p;
        ghostMaxPrice = p;
    }

    /// @notice Simulates trade volume moving the price by up to MAX_DEVIATION_BPS.
    function updatePrice(uint256 bpsSeed, bool up) external {
        uint256 old = model.spotPrice();
        uint256 bps = bound(bpsSeed, 0, model.MAX_DEVIATION_BPS());
        uint256 delta = (old * bps) / model.BPS();

        uint256 next = up ? old + delta : old - delta;
        if (next > model.MAX_PRICE()) next = model.MAX_PRICE();
        if (next < model.MIN_PRICE()) next = model.MIN_PRICE();

        model.updatePrice(next);

        uint256 diff = next > old ? next - old : old - next;
        uint256 devBps = (diff * model.BPS()) / old;
        if (devBps > ghostMaxDeviationBps) ghostMaxDeviationBps = devBps;
        if (next < ghostMinPrice) ghostMinPrice = next;
        if (next > ghostMaxPrice) ghostMaxPrice = next;
    }

    /// @notice Advances block time by 1 second up to 1 hour.
    function warp(uint256 dtSeed) external {
        uint256 dt = bound(dtSeed, 1, 1 hours);
        ghostCumulative += model.spotPrice() * dt;
        vm.warp(block.timestamp + dt);
    }
}
