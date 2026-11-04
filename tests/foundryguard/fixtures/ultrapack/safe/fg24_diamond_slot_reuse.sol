// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

library LibStaking {
    bytes32 internal constant STAKING_POSITION = keccak256("diamond.app.storage");

    struct Layout {
        uint256 totalStaked;
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 p = STAKING_POSITION;
        assembly {
            l.slot := p
        }
    }
}

library LibRewards {
    bytes32 internal constant REWARDS_POSITION = keccak256("diamond.app.rewards");

    struct Layout {
        address rewardToken;
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 p = REWARDS_POSITION;
        assembly {
            l.slot := p
        }
    }
}
