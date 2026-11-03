// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CommonBase} from "forge-std/Base.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {
    IERC20Minimal,
    TransientStaking,
    LeakyTransientStaking
} from "../../src/transient-vault/TransientStaking.sol";

/// @notice Mintable token the staking tests run on.
contract TransientStakingToken is IERC20Minimal {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice TransientStaking with a view that reads its own transient storage. A test contract cannot
///         read another contract's transient slots, so the check has to run in the vault's context.
contract TransientStakingHarness is TransientStaking {
    constructor(IERC20Minimal token_) TransientStaking(token_) { }

    function watchedSlots() external pure returns (bytes32[2] memory) {
        return [LOCK_SLOT, ENTRY_SLOT];
    }

    function transientSlot(bytes32 slot) external view returns (uint256 value) {
        assembly {
            value := tload(slot)
        }
    }
}

/// @notice The same view on the version with the planted bug.
contract LeakyTransientStakingHarness is LeakyTransientStaking {
    constructor(IERC20Minimal token_) LeakyTransientStaking(token_) { }

    function watchedSlots() external pure returns (bytes32[2] memory) {
        return [LOCK_SLOT, ENTRY_SLOT];
    }

    function transientSlot(bytes32 slot) external view returns (uint256 value) {
        assembly {
            value := tload(slot)
        }
    }
}

/// @notice Drives TransientStaking with single calls and with multicalls of two to four steps, so
///         several calls run inside one transaction. After every top-level call, while that
///         transaction is still running, it reads the lock and entry slots: both must be zero, or the
///         next call in the transaction would see a value that belongs to a call that has finished.
contract TransientHandler is CommonBase, StdUtils {
    TransientStakingHarness public immutable vault;
    TransientStakingToken public immutable token;

    uint256 public constant MAX_STAKE = 1e24;
    uint256 public constant INITIAL_BALANCE = 1e30;

    address[] public actors;

    /// Slot reads that found a value left behind by a call that had already returned.
    uint256 public ghostLeaks;
    bytes32 public ghostLeakSlot;
    uint256 public ghostChecks;
    uint256 public ghostMulticalls;
    uint256 public ghostStaked;
    uint256 public ghostUnstaked;

    constructor(TransientStakingHarness _vault, TransientStakingToken _token) {
        vault = _vault;
        token = _token;
        for (uint256 i = 0; i < 4; i++) {
            address actor = address(uint160(0x5000 + i));
            actors.push(actor);
            token.mint(actor, INITIAL_BALANCE);
            vm.prank(actor);
            token.approve(address(_vault), type(uint256).max);
        }
    }

    function actorCount() external view returns (uint256) {
        return actors.length;
    }

    function stake(uint256 actorSeed, uint256 amountSeed) external {
        address actor = _actor(actorSeed);
        uint256 amount = bound(amountSeed, 1, MAX_STAKE);
        vm.prank(actor);
        vault.stake(amount);
        ghostStaked += amount;
        _checkSlots();
    }

    function unstake(uint256 actorSeed, uint256 amountSeed) external {
        address actor = _actor(actorSeed);
        uint256 staked = vault.stakedOf(actor);
        if (staked == 0) return;
        uint256 amount = bound(amountSeed, 1, staked);
        vm.prank(actor);
        vault.unstake(amount);
        ghostUnstaked += amount;
        _checkSlots();
    }

    function claimPoints(uint256 actorSeed) external {
        vm.prank(_actor(actorSeed));
        vault.claimPoints();
        _checkSlots();
    }

    /// @notice Two to four stake / unstake / claimPoints steps through the vault's own multicall.
    function multicall(uint256 actorSeed, uint256 seed) external {
        address actor = _actor(actorSeed);
        uint256 steps = 2 + seed % 3;
        bytes[] memory calls = new bytes[](steps);
        uint256 staked = vault.stakedOf(actor);
        uint256 staking;
        uint256 unstaking;
        for (uint256 i = 0; i < steps; i++) {
            uint256 s = uint256(keccak256(abi.encode(seed, i)));
            uint256 op = s % 3;
            if (op == 1 && staked == 0) op = 0;
            if (op == 0) {
                uint256 amount = bound(s >> 8, 1, MAX_STAKE);
                calls[i] = abi.encodeCall(TransientStaking.stake, (amount));
                staked += amount;
                staking += amount;
            } else if (op == 1) {
                uint256 amount = bound(s >> 8, 1, staked);
                calls[i] = abi.encodeCall(TransientStaking.unstake, (amount));
                staked -= amount;
                unstaking += amount;
            } else {
                calls[i] = abi.encodeCall(TransientStaking.claimPoints, ());
            }
        }
        vm.prank(actor);
        vault.multicall(calls);
        ghostStaked += staking;
        ghostUnstaked += unstaking;
        ghostMulticalls++;
        _checkSlots();
    }

    function warp(uint256 dtSeed) external {
        vm.warp(block.timestamp + bound(dtSeed, 1, 3 days));
        vm.roll(block.number + 1);
    }

    function _checkSlots() internal {
        bytes32[2] memory slots = vault.watchedSlots();
        for (uint256 i = 0; i < slots.length; i++) {
            ghostChecks++;
            if (vault.transientSlot(slots[i]) != 0) {
                ghostLeaks++;
                ghostLeakSlot = slots[i];
            }
        }
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, actors.length - 1)];
    }
}
