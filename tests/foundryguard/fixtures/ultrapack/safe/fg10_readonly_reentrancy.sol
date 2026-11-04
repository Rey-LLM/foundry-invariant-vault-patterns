// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Pool {
    uint256 public totalShares;
    uint256 public totalAssets;
    bool private entered;

    modifier nonReentrant() {
        require(!entered);
        entered = true;
        _;
        entered = false;
    }

    function withdraw(uint256 s) external nonReentrant {
        require(s > 0 && totalShares > 0);
        uint256 a = s * totalAssets / totalShares;
        totalShares -= s;
        totalAssets -= a;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok);
    }

    function rate() external view returns (uint256) {
        return totalShares == 0 ? 1e18 : totalAssets * 1e18 / totalShares;
    }
}
