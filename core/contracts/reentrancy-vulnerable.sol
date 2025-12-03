// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: State change happens after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call - attacker can re-enter here
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State change AFTER external call - reentrancy vulnerability!
        balances[msg.sender] -= amount;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}