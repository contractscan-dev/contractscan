// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract SafeToken {
    string public constant name = "Safe"; string public constant symbol = "SAFE"; uint8 public constant decimals = 18;
    uint256 public immutable totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    constructor(uint256 supply) { totalSupply = supply; balanceOf[msg.sender] = supply; emit Transfer(address(0), msg.sender, supply); }
    function transfer(address to, uint256 v) external returns (bool) { _t(msg.sender, to, v); return true; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; emit Approval(msg.sender, s, v); return true; }
    function transferFrom(address f, address to, uint256 v) external returns (bool) { allowance[f][msg.sender] -= v; _t(f, to, v); return true; }
    function _t(address f, address to, uint256 v) internal { require(to != address(0), "zero"); balanceOf[f] -= v; balanceOf[to] += v; emit Transfer(f, to, v); }
}
