// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RandomnessVulnerable {
    address public owner;
    uint256 public prize;

    constructor() payable {
        owner = msg.sender;
        prize = msg.value;
    }

    // VULNERABLE: Using block.number for randomness
    function play() public {
        uint256 random = uint256(blockhash(block.number - 1)) % 10;

        if (random == 7) {
            payable(msg.sender).transfer(prize);
            prize = 0;
        }
    }

    // VULNERABLE: Using block properties for lottery
    function lottery() public view returns (uint256) {
        return
            uint256(
                keccak256(abi.encodePacked(block.difficulty, block.timestamp))
            ) % 100;
    }

    receive() external payable {
        prize += msg.value;
    }
}
