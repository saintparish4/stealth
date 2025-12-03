// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginVulnerable {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Using tx.origin for authentication
    function withdrawAll(address payable recipient) public {
        // tx.origin can be exploited via phishing attacks - vulnerability!
        require(tx.origin == owner, "Not owner");
        
        recipient.transfer(address(this).balance);
    }
    
    receive() external payable {}
}