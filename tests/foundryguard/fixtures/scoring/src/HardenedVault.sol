// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// The fixed counterpart of WeakVault: input checks, access control, effects before interactions.
contract HardenedVault {
    error ZeroAmount();
    error ZeroAddress();
    error NotOwner();
    error Locked();

    IERC20 public immutable asset;
    address public owner;
    uint256 public feeBps;
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;
    uint256 private locked = 1;

    event FeeSet(uint256 feeBps);
    event OwnerSet(address owner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (locked != 1) revert Locked();
        locked = 2;
        _;
        locked = 1;
    }

    constructor(IERC20 asset_) {
        if (address(asset_) == address(0)) revert ZeroAddress();
        asset = asset_;
        owner = msg.sender;
    }

    function setFee(uint256 newFee) external onlyOwner {
        if (newFee > 1_000) revert ZeroAmount();
        feeBps = newFee;
        emit FeeSet(newFee);
    }

    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
        emit OwnerSet(newOwner);
    }

    function deposit(uint256 assets) external nonReentrant {
        if (assets == 0) revert ZeroAmount();
        uint256 minted = (totalShares == 0 || totalAssets == 0) ? assets : assets * totalShares / totalAssets;
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += assets;
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer");
    }

    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0 || shares[msg.sender] < amount || totalShares == 0) revert ZeroAmount();
        uint256 out = amount * totalAssets / totalShares;
        shares[msg.sender] -= amount;
        totalShares -= amount;
        totalAssets -= out;
        require(asset.transfer(msg.sender, out), "transfer");
    }
}
