pragma solidity ^0.4.21;

contract Random {

    bool public isSolved = false;
    uint8 public seed;

    constructor() public {
        seed = _generateRandomSeed(251);
    }

    function _generateRandomSeed(uint8 modulus) internal view returns (uint8){
        return uint8(uint256(keccak256(abi.encodePacked(block.number , block.difficulty))) % modulus);
    }

    function solve(uint8 n) public returns (bool) {
        uint8 random = uint8(uint256(keccak256(abi.encodePacked(block.timestamp, seed))));

        if (n == random) {
            isSolved = true;
        }

        return isSolved;
    }

  
}