// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/finance/VestingWallet.sol";
contract TeamVesting is VestingWallet { constructor(address b, uint64 s) VestingWallet(b, s, 365 days) {} }
