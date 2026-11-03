// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Vulnerable: the redemption price is read straight off the vault's live token balance, so a bare
///         donation (a direct transfer, no deposit) moves it. A flash loan squeezes that: borrow, donate to
///         push the quote, mint/redeem against the wrong price, withdraw the donation, repay.
contract SpotPricedVault {
    IERC20 public immutable token;
    mapping(address => uint256) public sharesOf;
    uint256 public totalSupply;

    constructor(IERC20 token_) {
        token = token_;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        uint256 shares = totalSupply == 0 ? amount : amount * totalSupply / _backing();
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
        sharesOf[msg.sender] += shares;
        totalSupply += shares;
    }

    function withdraw(uint256 shares) external {
        require(sharesOf[msg.sender] >= shares, "balance");
        uint256 amount = convertToAssets(shares);
        sharesOf[msg.sender] -= shares;
        totalSupply -= shares;
        require(token.transfer(msg.sender, amount), "transfer");
    }

    /// @dev Spot price: assets per share = live balance / shares. A donation inflates the numerator.
    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) return shares;
        return shares * _backing() / totalSupply;
    }

    function _backing() internal view returns (uint256) {
        return token.balanceOf(address(this));
    }
}

/// @notice Fixed: redemptions are priced off internal accounting that only deposits and withdrawals change,
///         so an unsolicited donation does not move the quote. `skimmable()` still reads the live balance (to
///         report the surplus a keeper could sweep), which is why FoundryGuard still runs the squeeze check.
contract AccountedVault {
    IERC20 public immutable token;
    mapping(address => uint256) public sharesOf;
    uint256 public totalSupply;
    uint256 public totalManaged; // assets the vault counts as backing shares; ignores donations

    constructor(IERC20 token_) {
        token = token_;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        uint256 shares = totalSupply == 0 ? amount : amount * totalSupply / totalManaged;
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
        sharesOf[msg.sender] += shares;
        totalSupply += shares;
        totalManaged += amount;
    }

    function withdraw(uint256 shares) external {
        require(sharesOf[msg.sender] >= shares, "balance");
        uint256 amount = convertToAssets(shares);
        sharesOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalManaged -= amount;
        require(token.transfer(msg.sender, amount), "transfer");
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        if (totalSupply == 0) return shares;
        return shares * totalManaged / totalSupply;
    }

    /// @dev Reads the live balance, but only to report a surplus - never to price a redemption.
    function skimmable() external view returns (uint256) {
        uint256 bal = token.balanceOf(address(this));
        return bal > totalManaged ? bal - totalManaged : 0;
    }
}
