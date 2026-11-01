// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PriceOracleModel
/// @notice Reference model of a cumulative-price TWAP oracle with strict
///         boundary constraints. For education and testing only.
contract PriceOracleModel {
    struct Observation {
        uint64 timestamp;   // when this observation became effective
        uint256 cumulative; // price * seconds summed up to `timestamp`
        uint256 price;      // spot price in effect from `timestamp` onward
    }

    uint256 public constant BPS = 10_000;
    uint256 public constant MIN_PRICE = 1e6;
    uint256 public constant MAX_PRICE = 1e30;
    uint256 public constant MAX_DEVIATION_BPS = 1_000; // max 10% move per update

    uint256 public spotPrice;
    uint256 public priceCumulative;
    uint64 public lastUpdate;
    Observation[] internal _observations;

    event PriceUpdated(uint256 oldPrice, uint256 newPrice, uint64 timestamp);

    error PriceOutOfBounds(uint256 price);
    error DeviationTooLarge(uint256 oldPrice, uint256 newPrice);
    error InvalidWindow(uint256 window);

    constructor(uint256 initialPrice) {
        _checkBounds(initialPrice);
        spotPrice = initialPrice;
        lastUpdate = uint64(block.timestamp);
        _observations.push(Observation(lastUpdate, 0, initialPrice));
    }

    // ---------------------------------------------------------------- writes

    function updatePrice(uint256 newPrice) external {
        _checkBounds(newPrice);
        uint256 old = spotPrice;
        uint256 diff = newPrice > old ? newPrice - old : old - newPrice;
        if (diff * BPS > old * MAX_DEVIATION_BPS) revert DeviationTooLarge(old, newPrice);

        _accumulate();
        spotPrice = newPrice;

        uint256 last = _observations.length - 1;
        if (_observations[last].timestamp == lastUpdate) {
            // same-second update: overwrite the price that applies from now on
            _observations[last].price = newPrice;
        } else {
            _observations.push(Observation(lastUpdate, priceCumulative, newPrice));
        }
        emit PriceUpdated(old, newPrice, lastUpdate);
    }

    // ----------------------------------------------------------------- views

    function currentCumulative() public view returns (uint256) {
        return priceCumulative + spotPrice * (block.timestamp - lastUpdate);
    }

    function observationCount() external view returns (uint256) {
        return _observations.length;
    }

    function observation(uint256 i) external view returns (Observation memory) {
        return _observations[i];
    }

    function firstTimestamp() public view returns (uint64) {
        return _observations[0].timestamp;
    }

    /// @notice Time-weighted average price over the last `window` seconds.
    function consult(uint256 window) external view returns (uint256) {
        if (window == 0 || window > block.timestamp - firstTimestamp()) revert InvalidWindow(window);
        uint256 target = block.timestamp - window;
        return (currentCumulative() - _cumulativeAt(target)) / window;
    }

    // -------------------------------------------------------------- internal

    function _accumulate() internal {
        uint64 nowTs = uint64(block.timestamp);
        uint64 elapsed = nowTs - lastUpdate;
        if (elapsed > 0) {
            priceCumulative += spotPrice * elapsed;
            lastUpdate = nowTs;
        }
    }

    /// @dev Binary search for the latest observation with timestamp <= t,
    ///      then extrapolate with its (constant) price.
    function _cumulativeAt(uint256 t) internal view returns (uint256) {
        uint256 lo = 0;
        uint256 hi = _observations.length - 1;
        while (lo < hi) {
            uint256 mid = (lo + hi + 1) / 2;
            if (_observations[mid].timestamp <= t) lo = mid;
            else hi = mid - 1;
        }
        Observation memory o = _observations[lo];
        return o.cumulative + o.price * (t - o.timestamp);
    }

    function _checkBounds(uint256 p) internal pure {
        if (p < MIN_PRICE || p > MAX_PRICE) revert PriceOutOfBounds(p);
    }
}
