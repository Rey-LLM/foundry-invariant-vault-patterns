// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

/// Deliberately weak: every Layer 10 rule should find something here.
contract WeakVault {
    IERC20 public asset;
    IPair public pair;
    address public owner;
    uint256 public feeBps;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(IERC20 asset_, IPair pair_) {
        asset = asset_;
        pair = pair_;
        owner = msg.sender;
    }

    function setFee(uint256 newFee) external {
        feeBps = newFee;
    }

    function setOwner(address newOwner) external {
        require(tx.origin == owner, "not owner");
        owner = newOwner;
    }

    function deposit(uint256 assets) external {
        uint256 minted = totalShares == 0 ? assets : assets * totalShares / asset.balanceOf(address(this));
        asset.transferFrom(msg.sender, address(this), assets);
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function withdrawEth(uint256 amount) external {
        require(shares[msg.sender] >= amount, "balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }

    function sweep(address to) external {
        to.call("");
    }

    function spotPrice() external view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / r0;
    }

    function sharePrice() external view returns (uint256) {
        return asset.balanceOf(address(this)) / totalShares;
    }

    function ping(uint256 x) external returns (uint256) {
        return x + 1;
    }

    function donate() external payable {
        totalShares = totalShares;
    }
}

contract LeakyLock {
    uint256 constant LOCK = 0x1f;

    function enter() external {
        assembly {
            tstore(LOCK, 1)
        }
    }
}
