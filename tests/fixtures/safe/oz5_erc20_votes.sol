// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
contract MyToken is ERC20, ERC20Permit, ERC20Votes {
    constructor() ERC20("MyToken", "MTK") ERC20Permit("MyToken") { _mint(msg.sender, 1e24); }
    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Votes) { super._update(from, to, value); }
    function nonces(address owner) public view override(ERC20Permit, Nonces) returns (uint256) { return super.nonces(owner); }
}
