// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
contract My1155 is ERC1155, Ownable, ERC1155Supply {
    constructor(address o) ERC1155("ipfs://x/{id}") Ownable(o) {}
    function setURI(string memory u) public onlyOwner { _setURI(u); }
    function mint(address a, uint256 id, uint256 amt, bytes memory d) public onlyOwner { _mint(a, id, amt, d); }
    function _update(address f, address t, uint256[] memory ids, uint256[] memory v) internal override(ERC1155, ERC1155Supply) { super._update(f, t, ids, v); }
}
