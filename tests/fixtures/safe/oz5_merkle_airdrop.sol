// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
contract MerkleAirdrop {
    using SafeERC20 for IERC20;
    IERC20 public immutable token; bytes32 public immutable root; mapping(address => bool) public claimed;
    constructor(IERC20 t, bytes32 r) { token = t; root = r; }
    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "claimed");
        require(MerkleProof.verify(proof, root, keccak256(bytes.concat(keccak256(abi.encode(msg.sender, amount))))), "proof");
        claimed[msg.sender] = true; token.safeTransfer(msg.sender, amount);
    }
}
