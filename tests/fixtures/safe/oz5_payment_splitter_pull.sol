// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
contract PullPayments is ReentrancyGuard {
    mapping(address => uint256) public credit;
    function deposit(address payee) external payable { credit[payee] += msg.value; }
    function withdraw() external nonReentrant { uint256 a = credit[msg.sender]; credit[msg.sender] = 0; Address.sendValue(payable(msg.sender), a); }
}
