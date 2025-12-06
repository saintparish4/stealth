// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimestampVulnerable {
    address public owner;
    uint256 public prize;

    constructor() payable {
        owner = msg.sender;
        prize = msg.value;
    }

    // VULNERABLE: Using block.timestamp for exact timing
    function claimPrize() public {
        require(block.timestamp % 15 == 0, "Not the right time");
        payable(msg.sender).transfer(prize);
        prize = 0;
    }

    // VULNERABLE: Using block.timestamp in critical logic
    function isEligible() public view returns (bool) {
        return block.timestamp > 1700000000 && block.timestamp < 1800000000;
    }

    receive() external payable {
        prize += msg.value;
    }
}
