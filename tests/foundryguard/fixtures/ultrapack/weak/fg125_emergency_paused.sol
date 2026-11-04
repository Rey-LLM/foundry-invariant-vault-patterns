// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Pool {
    bool public paused;
    mapping(address => uint256) public balances;

    modifier whenNotPaused() { require(!paused); _; }

    function emergencyWithdraw() external whenNotPaused {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
