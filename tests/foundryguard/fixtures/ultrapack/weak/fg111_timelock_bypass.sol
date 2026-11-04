// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Timelock {
    address public admin = msg.sender;
    mapping(bytes32 => uint256) public eta;

    function queue(address target, bytes calldata data) external {
        require(msg.sender == admin);
        eta[keccak256(abi.encode(target, data))] = block.timestamp + 2 days;
    }

    function execute(address target, bytes calldata data) external {
        require(msg.sender == admin);
        bytes32 id = keccak256(abi.encode(target, data));
        require(eta[id] != 0, "unknown");
        delete eta[id];
        (bool ok, ) = target.call(data);
        require(ok);
    }
}
