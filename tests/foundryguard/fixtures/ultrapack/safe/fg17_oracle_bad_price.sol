// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }

contract Sample {
    IFeed public feed;

    function price() external view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(block.timestamp - updatedAt < 3600);
        require(answer > 0);
        return uint256(answer);
    }
}
