// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.7.0;

import "./Staking.sol";

contract Setup {

	StakingPool public staking;

	constructor() payable {
        require(msg.value == 100 ether);

        staking = new StakingPool();
        staking.linearAddPool(0, 3);
        payable(address(staking)).transfer(msg.value);
    }

    function isSolved() external view returns (bool) {
        return address(staking).balance == 0;
    }
}