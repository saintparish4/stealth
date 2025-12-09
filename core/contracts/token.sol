// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ExampleToken {
    mapping(address => uint256) public balances;
    string public name = "Example Token";
    string public symbol = "EXT";

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) public {
        // Vulnerable: Missing access control
        balances[to] += amount;
    }
}
