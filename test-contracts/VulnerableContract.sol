// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY 1: Reentrancy Attack
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state change - VULNERABLE!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount; // State change after external call
    }
    
    // VULNERABILITY 2: Integer Overflow (if using older Solidity)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // Could overflow in older versions
    }
    
    // VULNERABILITY 3: Unchecked Call Return Value
    function unsafeTransfer(address payable to, uint256 amount) public {
        to.call{value: amount}(""); // Return value not checked
    }
    
    // VULNERABILITY 4: Access Control Issue
    function changeOwner(address newOwner) public {
        // Missing access control - anyone can change owner!
        owner = newOwner;
    }
    
    // VULNERABILITY 5: Timestamp Dependence
    function timestampLottery() public view returns (bool) {
        // Using block.timestamp for randomness - VULNERABLE!
        return block.timestamp % 2 == 0;
    }
    
    // VULNERABILITY 6: DoS with Gas Limit
    address[] public participants;
    
    function distributeRewards() public {
        // Unbounded loop - can run out of gas
        for (uint i = 0; i < participants.length; i++) {
            payable(participants[i]).transfer(1 ether);
        }
    }
    
    function addParticipant(address participant) public {
        participants.push(participant);
    }
    
    // VULNERABILITY 7: Front-running
    function commitReveal(bytes32 commitment) public payable {
        // Simple commitment without proper reveal mechanism
        // Vulnerable to front-running attacks
        require(msg.value == 1 ether, "Must send 1 ether");
        // Process commitment...
    }
    
    // VULNERABILITY 8: Unprotected Self-Destruct
    function destroy() public {
        // No access control on self-destruct!
        selfdestruct(payable(msg.sender));
    }
    
    // Helper function to deposit funds
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    receive() external payable {
        deposit();
    }
}