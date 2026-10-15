// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol";
contract Wrapped is ERC20Wrapper { constructor(IERC20 u) ERC20("Wrapped", "wTKN") ERC20Wrapper(u) {} }
