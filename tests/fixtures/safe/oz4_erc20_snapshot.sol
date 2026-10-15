// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract SnapToken is ERC20, ERC20Snapshot, Ownable {
    constructor() ERC20("Snap", "SNP") { _mint(msg.sender, 1e24); }
    function snapshot() public onlyOwner { _snapshot(); }
    function _beforeTokenTransfer(address f, address t, uint256 a) internal override(ERC20, ERC20Snapshot) { super._beforeTokenTransfer(f, t, a); }
}
