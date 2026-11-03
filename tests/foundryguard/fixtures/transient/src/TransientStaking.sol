// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title TransientStaking
/// @notice Stakers earn points for every day their tokens stay staked, plus a one-off entry bonus of
///         1% of each new stake. Two values live in EIP-1153 transient storage for the length of one
///         call: the reentrancy lock, and the amount the running stake brings in, which `_accrue` turns
///         into the entry bonus. Both are cleared before the call returns, so the next call in the same
///         transaction (`multicall` below, a router, a callback) starts clean.
/// @dev Transient storage is only cleared when the transaction ends. A slot left set at the end of a
///      call is still there for every later call in that transaction.
contract TransientStaking {
    uint256 public constant ENTRY_BONUS_BPS = 100;

    /// @dev keccak256("transient-vault.lock") - 1
    bytes32 internal constant LOCK_SLOT = 0xb5b3158153d0aaada99ce72b624e94e7a176c6db390b7f301526554778835892;
    /// @dev keccak256("transient-vault.entry") - 1
    bytes32 internal constant ENTRY_SLOT = 0x42921539d5967844d1f3f10ed40f47d09e34318dd2aa14b0efc78898cdbcf2ba;

    IERC20Minimal public immutable stakingToken;

    uint256 public totalStaked;
    uint256 public totalPoints;
    mapping(address => uint256) public stakedOf;
    mapping(address => uint256) public pointsOf;
    mapping(address => uint256) public lastAccrual;

    error Reentrancy();
    error ZeroAmount();
    error InsufficientStake();
    error TransferFailed();

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event PointsAccrued(address indexed user, uint256 points);

    constructor(IERC20Minimal token_) {
        stakingToken = token_;
    }

    modifier nonReentrant() {
        bool locked;
        assembly {
            locked := tload(LOCK_SLOT)
        }
        if (locked) revert Reentrancy();
        assembly {
            tstore(LOCK_SLOT, 1)
        }
        _;
        assembly {
            tstore(LOCK_SLOT, 0)
        }
    }

    function stake(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        assembly {
            tstore(ENTRY_SLOT, amount)
        }
        _accrue(msg.sender);
        if (!stakingToken.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        stakedOf[msg.sender] += amount;
        totalStaked += amount;
        _endEntry();
        emit Staked(msg.sender, amount);
    }

    function unstake(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (amount > stakedOf[msg.sender]) revert InsufficientStake();
        _accrue(msg.sender);
        stakedOf[msg.sender] -= amount;
        totalStaked -= amount;
        if (!stakingToken.transfer(msg.sender, amount)) revert TransferFailed();
        emit Unstaked(msg.sender, amount);
    }

    /// @notice Books the points earned so far and returns the caller's total.
    function claimPoints() external nonReentrant returns (uint256) {
        _accrue(msg.sender);
        return pointsOf[msg.sender];
    }

    /// @notice Runs several calls on this contract in one transaction.
    function multicall(bytes[] calldata calls) external returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(calls[i]);
            if (!ok) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            results[i] = ret;
        }
    }

    /// @dev Time points since the last accrual, plus the entry bonus of the stake that is running.
    function _accrue(address user) internal {
        uint256 earned;
        uint256 last = lastAccrual[user];
        if (last != 0) earned = (stakedOf[user] * (block.timestamp - last)) / 1 days;
        uint256 entry;
        assembly {
            entry := tload(ENTRY_SLOT)
        }
        earned += (entry * ENTRY_BONUS_BPS) / 10_000;
        lastAccrual[user] = block.timestamp;
        if (earned != 0) {
            pointsOf[user] += earned;
            totalPoints += earned;
            emit PointsAccrued(user, earned);
        }
    }

    /// @dev Closes the entry-bonus window of a stake.
    function _endEntry() internal virtual {
        assembly {
            tstore(ENTRY_SLOT, 0)
        }
    }
}

/// @title LeakyTransientStaking
/// @notice Planted bug. It skips clearing ENTRY_SLOT to save gas, on the idea that EIP-1153 clears
///         transient storage anyway. It does, but only when the transaction ends. Until then every call
///         that accrues points reads the last stake amount and pays the entry bonus again:
///         `multicall([stake(x), claimPoints(), claimPoints()])` pays it three times.
contract LeakyTransientStaking is TransientStaking {
    constructor(IERC20Minimal token_) TransientStaking(token_) { }

    function _endEntry() internal override { }
}
