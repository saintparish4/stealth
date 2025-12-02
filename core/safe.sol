// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: State change happens BEFORE external call 
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State change FIRST - follows checks-effects-interactions pattern 
        balances[msg.sender] -= amount;

        // External call happens AFTER state change - safe! 
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}