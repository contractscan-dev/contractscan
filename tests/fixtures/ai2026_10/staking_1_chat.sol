// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleStaking
 * @notice Stake an ERC20 token and earn more of the same token at a fixed 20% APR.
 *         Rewards accrue per second based on each user's staked balance.
 *         Users can stake, unstake, and claim rewards at any time.
 */
contract SimpleStaking {
    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    /// @dev Fixed APR: 20% -> 20/100.  Scaled by 1e18 for precision.
    uint256 public constant APR_BPS = 2000;          // 2000 basis points = 20%
    uint256 public constant BPS_DENOMINATOR = 10000; // 100% = 10000 bps
    uint256 public constant SECONDS_PER_YEAR = 365 days;

    /// @dev reward-per-token accumulator precision.
    uint256 private constant ACC_PRECISION = 1e18;

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    /// @notice The ERC20 token staked and rewarded.
    IERC20 public immutable stakingToken;

    /// @notice Total tokens currently staked.
    uint256 public totalStaked;

    /// @notice Reward-per-token accumulator (scaled by ACC_PRECISION).
    ///         Increases every time someone interacts, at the global rate.
    uint256 public accRewardPerToken;

    /// @notice Timestamp of the last update to accRewardPerToken.
    uint256 public lastUpdateTime;

    struct StakeInfo {
        uint256 amount;             // staked balance
        uint256 rewardDebt;         // accRewardPerToken * amount / ACC_PRECISION at last update
        uint256 pendingRewards;     // rewards stored from previous epochs / claims
    }

    mapping(address => StakeInfo) public stakes;

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    error ZeroAmount();
    error InsufficientStake();
    error TransferFailed();

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    constructor(address _stakingToken) {
        require(_stakingToken != address(0), "invalid token");
        stakingToken = IERC20(_stakingToken);
        lastUpdateTime = block.timestamp;
    }

    // ------------------------------------------------------------------
    // Internal: rate / accrual logic
    // ------------------------------------------------------------------

    /// @dev Reward tokens emitted per second for the whole pool.
    function _rewardRatePerSecond() internal view returns (uint256) {
        if (totalStaked == 0) return 0;
        // totalStaked * APR_BPS / BPS_DENOMINATOR / SECONDS_PER_YEAR
        return (totalStaked * APR_BPS) / (BPS_DENOMINATOR * SECONDS_PER_YEAR);
    }

    /// @dev Advance the global accumulator up to `block.timestamp`.
    ///      Must be called before any user balance mutation.
    function _updateRewards() internal {
        uint256 nowTs = block.timestamp;
        if (nowTs == lastUpdateTime || totalStaked == 0) {
            lastUpdateTime = nowTs;
            return;
        }

        uint256 elapsed = nowTs - lastUpdateTime;
        uint256 rate = _rewardRatePerSecond();
        if (rate == 0) {
            lastUpdateTime = nowTs;
            return;
        }

        uint256 reward = rate * elapsed;
        // accRewardPerToken += reward * ACC_PRECISION / totalStaked
        accRewardPerToken += (reward * ACC_PRECISION) / totalStaked;

        lastUpdateTime = nowTs;
    }

    /// @dev Rewards accrued to a user since their last checkpoint,
    ///      plus anything carried in pendingRewards.
    function _pendingOf(address user) internal view returns (uint256) {
        StakeInfo storage s = stakes[user];
        if (s.amount == 0) return s.pendingRewards;

        // Simulate accRewardPerToken at current time without mutating state.
        uint256 acc = accRewardPerToken;
        uint256 nowTs = block.timestamp;
        if (nowTs > lastUpdateTime && totalStaked > 0) {
            uint256 rate = _rewardRatePerSecond();
            uint256 elapsed = nowTs - lastUpdateTime;
            acc += (rate * elapsed * ACC_PRECISION) / totalStaked;
        }

        uint256 accrued = (s.amount * acc) / ACC_PRECISION;
        return s.pendingRewards + accrued - s.rewardDebt;
    }

    /// @dev Snapshot user's current rewards into pendingRewards and move
    ///      rewardDebt to current accumulator.  Call after _updateRewards().
    function _settle(address user) internal {
        StakeInfo storage s = stakes[user];
        if (s.amount > 0) {
            uint256 accrued = (s.amount * accRewardPerToken) / ACC_PRECISION;
            s.pendingRewards = s.pendingRewards + accrued - s.rewardDebt;
        }
        s.rewardDebt = (s.amount * accRewardPerToken) / ACC_PRECISION;
    }

    // ------------------------------------------------------------------
    // User actions
    // ------------------------------------------------------------------

    /// @notice Stake `amount` tokens.
    function stake(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();

        _updateRewards();
        _settle(msg.sender);

        stakes[msg.sender].amount += amount;
        stakes[msg.sender].rewardDebt =
            (stakes[msg.sender].amount * accRewardPerToken) / ACC_PRECISION;

        totalStaked += amount;

        _safeTransferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }

    /// @notice Unstake `amount` tokens.  Rewards stay claimable separately.
    function unstake(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        StakeInfo storage s = stakes[msg.sender];
        if (amount > s.amount) revert InsufficientStake();

        _updateRewards();
        _settle(msg.sender);

        s.amount -= amount;
        s.rewardDebt = (s.amount * accRewardPerToken) / ACC_PRECISION;

        totalStaked -= amount;

        _safeTransfer(msg.sender, amount);
        emit Unstaked(msg.sender, amount);
    }

    /// @notice Claim accrued rewards without touching the stake.
    function claimRewards() external {
        _updateRewards();
        _settle(msg.sender);

        StakeInfo storage s = stakes[msg.sender];
        uint256 reward = s.pendingRewards;
        if (reward == 0) return;

        s.pendingRewards = 0;
        _safeTransfer(msg.sender, reward);
        emit RewardClaimed(msg.sender, reward);
    }

    /// @notice Convenience: unstake everything and claim all rewards.
    function exit() external {
        StakeInfo storage s = stakes[msg.sender];
        uint256 amount = s.amount;
        uint256 reward;

        _updateRewards();
        _settle(msg.sender);

        reward = s.pendingRewards;
        s.pendingRewards = 0;
        s.amount = 0;
        s.rewardDebt = 0;

        totalStaked -= amount;

        if (amount > 0) {
            _safeTransfer(msg.sender, amount);
            emit Unstaked(msg.sender, amount);
        }
        if (reward > 0) {
            _safeTransfer(msg.sender, reward);
            emit RewardClaimed(msg.sender, reward);
        }
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    /// @notice Rewards currently claimable by `user`.
    function pendingRewards(address user) external view returns (uint256) {
        return _pendingOf(user);
    }

    /// @notice Total rewards the contract owes to stakers right now.
    function totalRewardsOwed() external view returns (uint256) {
        if (totalStaked == 0) return 0;

        uint256 acc = accRewardPerToken;
        uint256 nowTs = block.timestamp;
        if (nowTs > lastUpdateTime) {
            uint256 rate = _rewardRatePerSecond();
            acc += (rate * (nowTs - lastUpdateTime) * ACC_PRECISION) / totalStaked;
        }
        return (totalStaked * acc) / ACC_PRECISION;
    }

    // ------------------------------------------------------------------
    // Safe ERC20 helpers
    // ------------------------------------------------------------------

    function _safeTransfer(address to, uint256 amount) private {
        (bool ok, bytes memory data) = address(stakingToken).call(
            abi.encodeWithSelector(stakingToken.transfer.selector, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed();
        }
    }

    function _safeTransferFrom(address from, address to, uint256 amount) private {
        (bool ok, bytes memory data) = address(stakingToken).call(
            abi.encodeWithSelector(stakingToken.transferFrom.selector, from, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed();
        }
    }
}

// ------------------------------------------------------------------
// Minimal ERC20 interface (inlined to keep this file self-contained).
// ------------------------------------------------------------------
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
