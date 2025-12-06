// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MissingAccessControlSafe {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner);
        _;
    }

    function deposit() public payable {
        balance += msg.value; 
    }

    // SAFE: Has access control modifier 
    function withdraw(uint256 amount) public onlyOwner {
        require(balance >= amount, "Insufficient balance");
        payable(msg.sender).transfer(amount);
        balance -= amount; 
    }

    // SAFE: Has access control modifier 
    function destroy() public onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}