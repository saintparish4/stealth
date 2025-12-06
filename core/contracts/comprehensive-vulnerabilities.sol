// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract demonstrates ALL SEVEN vulnerability types - Phase 2.5
contract ComprehensiveVulnerabilities {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public prize;

    constructor() payable {
        owner = msg.sender;
        prize = msg.value;
    }

    // VULNERABILITY 1: Reentrancy (state change after external call)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount; // State change AFTER external call
    }

    // VULNERABILITY 2: Unchecked external call
    function forwardFunds(address payable recipient) public {
        recipient.call{value: address(this).balance}(""); // Not checking return value
    }

    // VULNERABILITY 3: tx.origin authentication
    function emergencyWithdraw() public {
        require(tx.origin == owner); // Using tx.origin instead of msg.sender
        payable(owner).transfer(address(this).balance);
    }

    // VULNERABILITY 4: Missing access control
    function destroy() public {
        selfdestruct(payable(msg.sender)); // No access control!
    }

    // VULNERABILITY 5: Dangerous delegatecall
    function execute(address target, bytes memory data) public {
        target.delegatecall(data); // User-controlled delegatecall
    }

    // VULNERABILITY 6: Timestamp dependence
    function claimPrize() public {
        require(block.timestamp % 15 == 0, "Not the right time"); // Exact timestamp check
        payable(msg.sender).transfer(prize);
    }

    // VULNERABILITY 7: Unsafe randomness
    function lottery() public {
        uint256 random = uint256(blockhash(block.number - 1)) % 100; // Predictable randomness
        if (random < 50) {
            payable(msg.sender).transfer(0.1 ether);
        }
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}
