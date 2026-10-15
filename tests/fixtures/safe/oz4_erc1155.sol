// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
contract Items is ERC1155, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    constructor() ERC1155("ipfs://x/{id}") { _grantRole(DEFAULT_ADMIN_ROLE, msg.sender); }
    function mint(address a, uint256 id, uint256 n) public onlyRole(MINTER_ROLE) { _mint(a, id, n, ""); }
    function supportsInterface(bytes4 i) public view override(ERC1155, AccessControl) returns (bool) { return super.supportsInterface(i); }
}
