// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Vulnerable: a vote is weighted by the voter's balance right now, so tokens flash-minted in the
///         same transaction count. An attacker borrows the governance token, votes, and returns it, all in
///         one transaction, and the proposal is decided by weight it never really held.
contract FlashVoteGovernor {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    mapping(uint256 => uint256) public forVotes;

    /// @dev Public on purpose: the model stands in for a token that can be flash-minted / flash-borrowed.
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    /// @dev Live weight: reads the current balance, which a flash loan has just inflated.
    function castVote(uint256 proposalId, bool support) external {
        uint256 weight = balanceOf[msg.sender];
        if (support) forVotes[proposalId] += weight;
    }

    function votingPower(address account) external view returns (uint256) {
        return balanceOf[account];
    }
}

/// @notice Fixed: voting power is the balance as of a block strictly before the current one. Tokens acquired
///         in this block do not count until a later block, so a same-transaction flash mint carries no weight.
contract SnapshotGovernor {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    mapping(uint256 => uint256) public forVotes;

    mapping(address => uint256) private _priorBalance; // balance as of the last block this account changed
    mapping(address => uint256) private _lastBlock;

    function _sync(address account) internal {
        if (_lastBlock[account] != block.number) {
            _priorBalance[account] = balanceOf[account];
            _lastBlock[account] = block.number;
        }
    }

    function mint(address to, uint256 amount) public {
        _sync(to);
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    /// @dev Past checkpoint: a balance change in the current block is not visible to voting power until the
    ///      next block, so flash-minted tokens cannot vote.
    function votingPower(address account) public view returns (uint256) {
        return _lastBlock[account] == block.number ? _priorBalance[account] : balanceOf[account];
    }

    function castVote(uint256 proposalId, bool support) external {
        uint256 weight = votingPower(msg.sender);
        if (support) forVotes[proposalId] += weight;
    }
}
