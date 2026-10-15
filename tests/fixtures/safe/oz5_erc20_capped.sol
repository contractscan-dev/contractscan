// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract CappedToken is ERC20Capped, Ownable {
    constructor() ERC20("Cap", "CAP") ERC20Capped(1e27) Ownable(msg.sender) {}
    function mint(address to, uint256 a) external onlyOwner { _mint(to, a); }
}
