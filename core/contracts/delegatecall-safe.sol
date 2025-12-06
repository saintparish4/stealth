// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DelegatecallSafe {
    address public owner;
    address public immutable trustedLibrary; // Hardcoded library address
    uint256 public value;

    constructor(address _trustedLibrary) {
        owner = msg.sender;
        trustedLibrary = _trustedLibrary;
    }

    // SAFE: delegatecall only to trusted, immutable address
    function executeCode(bytes memory data) public {
        (bool success, ) = trustedLibrary.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    function setValue(uint256 newValue) public {
        require(msg.sender == owner, "Not owner");
        value = newValue;
    }

    receive() external payable {}
}
