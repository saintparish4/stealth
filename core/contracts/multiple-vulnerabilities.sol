// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// This contract has ALL THREE vulnerabilities - good for testing
contract MultipleVulnerabilities {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY 1: Reentrancy (state change after external call)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] -= amount;  // State change AFTER external call
    }
    
    // VULNERABILITY 2: Unchecked external call
    function forwardFunds(address payable recipient) public {
        require(msg.sender == owner);
        
        recipient.call{value: address(this).balance}("");  // Not checking return value
    }
    
    // VULNERABILITY 3: tx.origin authentication
    function emergencyWithdraw() public {
        require(tx.origin == owner);  // Using tx.origin instead of msg.sender
        
        payable(owner).transfer(address(this).balance);
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    receive() external payable {}
}