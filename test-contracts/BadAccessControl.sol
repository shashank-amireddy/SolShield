// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BadAccessControl {
    address public admin;
    mapping(address => bool) public authorized;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    
    constructor() {
        admin = msg.sender;
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }
    
    // VULNERABILITY: Missing access control modifier
    function setAdmin(address newAdmin) public {
        // Anyone can become admin!
        admin = newAdmin;
    }
    
    // VULNERABILITY: Weak access control
    function authorize(address user) public {
        require(msg.sender == admin, "Only admin");
        // But admin can be changed by anyone (see above)
        authorized[user] = true;
    }
    
    // VULNERABILITY: Logic error in access control
    function transfer(address to, uint256 amount) public {
        // Wrong condition - should be ||, not &&
        require(authorized[msg.sender] && msg.sender == admin, "Not authorized");
        
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    // VULNERABILITY: Missing access control on critical function
    function mint(address to, uint256 amount) public {
        // No access control - anyone can mint tokens!
        totalSupply += amount;
        balances[to] += amount;
    }
    
    // VULNERABILITY: Inconsistent access control
    function burn(uint256 amount) public {
        // Only checks balance, not authorization
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }
    
    // VULNERABILITY: Race condition in authorization
    mapping(address => uint256) public pendingAuthorizations;
    
    function requestAuthorization() public payable {
        require(msg.value == 1 ether, "Must pay 1 ether");
        pendingAuthorizations[msg.sender] = block.timestamp;
    }
    
    function approveAuthorization(address user) public {
        require(msg.sender == admin, "Only admin");
        require(pendingAuthorizations[user] > 0, "No pending request");
        
        // VULNERABILITY: No time check, can approve old requests
        authorized[user] = true;
        delete pendingAuthorizations[user];
    }
}