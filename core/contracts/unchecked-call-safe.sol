// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCallSafe {
    address payable public owner;
    
    constructor() {
        owner = payable(msg.sender);
    }
    
    // SAFE: Call return value is checked
    function withdrawToOwner() public {
        require(msg.sender == owner, "Not owner");
        
        // External call WITH proper return value check - safe!
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    receive() external payable {}
}
