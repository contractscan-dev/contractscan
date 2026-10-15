// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
contract MyNFT is ERC721, Ownable {
    using Counters for Counters.Counter; Counters.Counter private _ids;
    constructor() ERC721("MyNFT", "NFT") {}
    function safeMint(address to) public onlyOwner { uint256 id = _ids.current(); _ids.increment(); _safeMint(to, id); }
}
