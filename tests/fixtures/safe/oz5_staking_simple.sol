// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
contract SimpleStaking is ReentrancyGuard {
    using SafeERC20 for IERC20;
    IERC20 public immutable stakingToken; mapping(address => uint256) public balanceOf; uint256 public totalStaked;
    constructor(IERC20 t) { stakingToken = t; }
    function stake(uint256 a) external nonReentrant { require(a > 0); totalStaked += a; balanceOf[msg.sender] += a; stakingToken.safeTransferFrom(msg.sender, address(this), a); }
    function withdraw(uint256 a) external nonReentrant { balanceOf[msg.sender] -= a; totalStaked -= a; stakingToken.safeTransfer(msg.sender, a); }
}
