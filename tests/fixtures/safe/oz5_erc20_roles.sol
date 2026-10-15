// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
contract MyToken is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    constructor(address admin, address minter) ERC20("MyToken", "MTK") { _grantRole(DEFAULT_ADMIN_ROLE, admin); _grantRole(MINTER_ROLE, minter); }
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) { _mint(to, amount); }
}
