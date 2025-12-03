// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginSafe {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // SAFE: Using msg.sender for authentication
    function withdrawAll(address payable recipient) public {
        // msg.sender is safe for authentication - correct!
        require(msg.sender == owner, "Not owner");
        
        recipient.transfer(address(this).balance);
    }
    
    receive() external payable {}
}