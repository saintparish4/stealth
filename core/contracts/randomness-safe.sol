// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RandomnessSafe {
    address public owner;
    uint256 public prize;

    // Commit-reveal scheme variables
    mapping(address => bytes32) public commits;
    mapping(address => uint256) public commitTimestamp;

    constructor() payable {
        owner = msg.sender;
        prize = msg.value;
    }

    // SAFE: Using commit-reveal scheme (step 1)
    function commit(bytes32 commitment) public {
        commits[msg.sender] = commitment;
        commitTimestamp[msg.sender] = block.timestamp;
    }

    // SAFE: Using commit-reveal scheme (step 2)
    function reveal(uint256 nonce) public {
        require(
            block.timestamp > commitTimestamp[msg.sender] + 1 minutes,
            "Too early"
        );
        require(
            commits[msg.sender] ==
                keccak256(abi.encodePacked(msg.sender, nonce)),
            "Invalid reveal"
        );

        // Use revealed nonce for randomness
        uint256 random = nonce % 10;

        if (random == 7) {
            payable(msg.sender).transfer(prize / 10); // Partial prize
        }

        delete commits[msg.sender];
        delete commitTimestamp[msg.sender];
    }

    // Better approach: Mention Chainlink VRF in comments
    // For production: Use Chainlink VRF for true randomness

    receive() external payable {
        prize += msg.value;
    }
}
