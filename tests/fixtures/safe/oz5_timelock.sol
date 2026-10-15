// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/governance/TimelockController.sol";
contract Timelock is TimelockController { constructor(address[] memory p, address[] memory e) TimelockController(2 days, p, e, address(0)) {} }
