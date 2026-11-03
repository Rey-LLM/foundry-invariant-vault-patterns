// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Vulnerable: withdraw sends the assets before it finishes updating accounting. During the payment
///         the caller gets control (a native receive / fallback) while the share count has been lowered but
///         the asset total has not, so pricePerShare reads a value that is true neither before the flow nor
///         after it. A lending market or AMM that reads that price mid-payment is misled (read-only
///         reentrancy).
contract NativeYieldVault {
    uint256 public totalShares;
    uint256 public totalAssets; // assets the vault accounts for (equals the ETH it holds between flows)
    mapping(address => uint256) public sharesOf;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        uint256 shares = totalShares == 0 ? msg.value : msg.value * totalShares / totalAssets;
        sharesOf[msg.sender] += shares;
        totalShares += shares;
        totalAssets += msg.value;
    }

    function withdraw(uint256 shares) external {
        require(sharesOf[msg.sender] >= shares, "balance");
        uint256 assets = totalShares == 0 ? 0 : shares * totalAssets / totalShares;
        // Shares are settled first, assets last - with the external payment wedged in between.
        totalShares -= shares;
        sharesOf[msg.sender] -= shares;
        (bool ok,) = msg.sender.call{value: assets}("");
        require(ok, "pay");
        totalAssets -= assets; // too late: the callback above already read a half-updated pricePerShare
    }

    function pricePerShare() external view returns (uint256) {
        return totalShares == 0 ? 1e18 : totalAssets * 1e18 / totalShares;
    }
}

/// @notice Fixed: checks-effects-interactions. All accounting is settled before the payment goes out, so the
///         views read the same pre- or post-flow state no matter when a reader looks.
contract SafeNativeYieldVault {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public sharesOf;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        uint256 shares = totalShares == 0 ? msg.value : msg.value * totalShares / totalAssets;
        sharesOf[msg.sender] += shares;
        totalShares += shares;
        totalAssets += msg.value;
    }

    function withdraw(uint256 shares) external {
        require(sharesOf[msg.sender] >= shares, "balance");
        uint256 assets = totalShares == 0 ? 0 : shares * totalAssets / totalShares;
        totalShares -= shares;
        sharesOf[msg.sender] -= shares;
        totalAssets -= assets;
        (bool ok,) = msg.sender.call{value: assets}("");
        require(ok, "pay");
    }

    function pricePerShare() external view returns (uint256) {
        return totalShares == 0 ? 1e18 : totalAssets * 1e18 / totalShares;
    }
}
