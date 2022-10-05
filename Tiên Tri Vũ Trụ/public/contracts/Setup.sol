// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.4.21;

import "./Random.sol";

contract Setup {

	Random public random;

	constructor() public{
        random = new Random();
    }

    function isSolved() external view returns (bool) {
        return random.isSolved();
    }
}