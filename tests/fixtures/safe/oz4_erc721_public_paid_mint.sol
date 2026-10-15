// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract PaidMint is ERC721, Ownable {
    uint256 public next; uint256 public constant PRICE = 0.05 ether; uint256 public constant MAX = 1000;
    constructor() ERC721("Paid", "PD") {}
    function mint() external payable { require(msg.value == PRICE && next < MAX); _safeMint(msg.sender, next++); }
    function withdraw() external onlyOwner { payable(owner()).transfer(address(this).balance); }
}
