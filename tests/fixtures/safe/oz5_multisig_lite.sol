// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
contract SignedMint {
    using ECDSA for bytes32;
    address public immutable signer; mapping(bytes32 => bool) public used; mapping(address => uint256) public points;
    constructor(address s) { signer = s; }
    function redeem(uint256 amt, bytes32 nonce, bytes calldata sig) external {
        bytes32 h = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(msg.sender, amt, nonce, address(this), block.chainid)));
        require(!used[nonce] && h.recover(sig) == signer, "bad"); used[nonce] = true; points[msg.sender] += amt;
    }
}
