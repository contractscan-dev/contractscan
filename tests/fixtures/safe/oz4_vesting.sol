// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
import "@openzeppelin/contracts/finance/VestingWallet.sol";
contract V is VestingWallet { constructor(address b) VestingWallet(b, uint64(block.timestamp), 365 days) {} }
