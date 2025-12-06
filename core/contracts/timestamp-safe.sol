// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimestampSafe {
    address public owner;
    uint256 public prize;
    uint256 public startTime;
    uint256 public endTime;

    constructor() payable {
        owner = msg.sender;
        prize = msg.value;
        startTime = block.timestamp;
        endTime = block.timestamp + 30 days; // Safe: reasonable tolerance
    }

    // SAFE: Using timestamp with reasonable tolerance (not exact timing)
    function claimPrize() public {
        require(block.timestamp >= endTime, "Too early");
        payable(msg.sender).transfer(prize);
        prize = 0;
    }

    // SAFE: Reasonable time range check
    function isEligible() public view returns (bool) {
        return block.timestamp >= startTime && block.timestamp <= endTime;
    }

    receive() external payable {
        prize += msg.value;
    }
}
