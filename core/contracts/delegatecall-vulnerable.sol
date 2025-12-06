// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DelegatecallVulnerable {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: delegatecall to user-provided address
    function executeCode(address target, bytes memory data) public {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // VULNERABLE: Can be used to change owner via delegatecall
    function setValue(uint256 newValue) public {
        value = newValue;
    }

    receive() external payable {}
}
