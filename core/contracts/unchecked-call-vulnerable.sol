// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCallVulnerable {
    address payable public owner;
    
    constructor() {
        owner = payable(msg.sender);
    }
    
    // VULNERABLE: Call return value is not checked
    function withdrawToOwner() public {
        require(msg.sender == owner, "Not owner");
        
        // External call without checking return value - vulnerability!
        owner.call{value: address(this).balance}("");
    }
    
    receive() external payable {}
}