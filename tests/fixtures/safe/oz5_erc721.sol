// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract MyNFT is ERC721, ERC721Enumerable, ERC721URIStorage, Ownable {
    uint256 private _nextTokenId;
    constructor(address o) ERC721("MyNFT", "NFT") Ownable(o) {}
    function safeMint(address to, string memory uri) public onlyOwner { uint256 id = _nextTokenId++; _safeMint(to, id); _setTokenURI(id, uri); }
    function _update(address to, uint256 id, address auth) internal override(ERC721, ERC721Enumerable) returns (address) { return super._update(to, id, auth); }
    function _increaseBalance(address a, uint128 v) internal override(ERC721, ERC721Enumerable) { super._increaseBalance(a, v); }
    function tokenURI(uint256 id) public view override(ERC721, ERC721URIStorage) returns (string memory) { return super.tokenURI(id); }
    function supportsInterface(bytes4 i) public view override(ERC721, ERC721Enumerable, ERC721URIStorage) returns (bool) { return super.supportsInterface(i); }
}
