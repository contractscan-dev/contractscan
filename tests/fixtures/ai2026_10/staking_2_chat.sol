// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleStakingPool
 * @notice Stake TOKEN, earn rewards streamed per second from a funded reward pool.
 *         Synthetix-style reward accounting, simplified.
 */
contract SimpleStakingPool {
    // ---------------------------------------------------------------------
    // Immutables / constants
    // ---------------------------------------------------------------------

    /// @notice The staking token users deposit.
    IERC20 public immutable stakingToken;

    /// @notice The reward token paid out.
    IERC20 public immutable rewardToken;

    /// @notice Contract owner (can fund rewards, recover unrelated tokens).
    address public owner;

    // ---------------------------------------------------------------------
    // Reward state
    // ---------------------------------------------------------------------

    /// @notice Timestamp at which the current reward period ends.
    uint256 public periodFinish;

    /// @notice Reward tokens distributed per second during the current period.
    uint256 public rewardRate;

    /// @notice Duration (seconds) over which newly funded rewards stream out.
    uint256 public rewardsDuration = 30 days;

    /// @notice Last time reward accounting was updated.
    uint256 public lastUpdateTime;

    /// @notice Accumulated rewards per staked token (scaled by 1e18).
    uint256 public rewardPerTokenStored;

    // ---------------------------------------------------------------------
    // Per-user state
    // ---------------------------------------------------------------------

    /// @notice Last cached rewardPerTokenStored for each user.
    mapping(address => uint256) public userRewardPerTokenPaid;
    /// @notice Rewards accrued but not yet claimed, per user.
    mapping(address => uint256) public rewards;

    /// @notice Total staked tokens.
    uint256 public totalSupply;
    /// @notice Individual stake balances.
    mapping(address => uint256) public balanceOf;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    event RewardAdded(uint256 reward, uint256 periodFinish);
    event RewardsDurationUpdated(uint256 newDuration);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ---------------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier updateReward(address account) {
        // First, roll rewardPerTokenStored forward to "now".
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = lastTimeRewardApplicable();
        // Then checkpoint the account (if any).
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor(address _stakingToken, address _rewardToken) {
        require(_stakingToken != address(0) && _rewardToken != address(0), "zero addr");
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    /// @notice Last time rewards are applicable (end of period or now).
    function lastTimeRewardApplicable() public view returns (uint256) {
        return block.timestamp < periodFinish ? block.timestamp : periodFinish;
    }

    /// @notice Current cumulative reward per staked token (1e18 scaled).
    function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) {
            return rewardPerTokenStored;
        }
        return rewardPerTokenStored +
            ((lastTimeRewardApplicable() - lastUpdateTime) * rewardRate * 1e18) / totalSupply;
    }

    /// @notice Total rewards accrued (unclaimed) for `account`.
    function earned(address account) public view returns (uint256) {
        return
            (balanceOf[account] * (rewardPerToken() - userRewardPerTokenPaid[account])) /
            1e18 +
            rewards[account];
    }

    /// @notice Amount currently claimable from the reward pool.
    function rewardPoolBalance() external view returns (uint256) {
        return rewardToken.balanceOf(address(this));
    }

    // ---------------------------------------------------------------------
    // User actions
    // ---------------------------------------------------------------------

    /// @notice Stake `amount` of staking tokens.
    function stake(uint256 amount) external updateReward(msg.sender) {
        require(amount > 0, "cannot stake 0");
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
        require(
            stakingToken.transferFrom(msg.sender, address(this), amount),
            "transferFrom failed"
        );
        emit Staked(msg.sender, amount);
    }

    /// @notice Withdraw `amount` of staked tokens (rewards are not auto-claimed).
    function withdraw(uint256 amount) public updateReward(msg.sender) {
        require(amount > 0, "cannot withdraw 0");
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        totalSupply -= amount;
        balanceOf[msg.sender] -= amount;
        require(stakingToken.transfer(msg.sender, amount), "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Claim accrued rewards.
    function claimReward() public updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        if (reward > 0) {
            rewards[msg.sender] = 0;
            require(rewardToken.transfer(msg.sender, reward), "reward transfer failed");
            emit RewardPaid(msg.sender, reward);
        }
    }

    /// @notice Withdraw everything and claim rewards in one call.
    function exit() external {
        withdraw(balanceOf[msg.sender]);
        claimReward();
    }

    // ---------------------------------------------------------------------
    // Owner actions
    // ---------------------------------------------------------------------

    /// @notice Fund the reward pool. Tokens must be transferred in beforehand.
    ///         Call: rewardToken.approve(pool, amount); pool.notifyRewardAmount(amount);
    function notifyRewardAmount(uint256 reward) external onlyOwner updateReward(address(0)) {
        // Roll over any leftover rewards from the previous period.
        if (block.timestamp >= periodFinish) {
            rewardRate = reward / rewardsDuration;
        } else {
            uint256 remaining = periodFinish - block.timestamp;
            uint256 leftover = remaining * rewardRate;
            rewardRate = (reward + leftover) / rewardsDuration;
        }

        // Ensure the contract actually holds enough reward tokens.
        uint256 balance = rewardToken.balanceOf(address(this));
        require(rewardRate <= balance / rewardsDuration, "reward too high");

        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + rewardsDuration;

        emit RewardAdded(reward, periodFinish);
    }

    /// @notice Change the streaming duration. Takes effect on next notifyRewardAmount.
    function setRewardsDuration(uint256 _rewardsDuration) external onlyOwner {
        require(block.timestamp > periodFinish, "period active");
        require(_rewardsDuration > 0, "zero duration");
        rewardsDuration = _rewardsDuration;
        emit RewardsDurationUpdated(_rewardsDuration);
    }

    /// @notice Transfer ownership.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero addr");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Recover tokens other than the staking / reward tokens.
    function recoverERC20(address token, uint256 amount) external onlyOwner {
        require(token != address(stakingToken) && token != address(rewardToken), "protected token");
        require(IERC20(token).transfer(owner, amount), "recover failed");
    }
}

// -------------------------------------------------------------------------
// Minimal IERC20 interface (self-contained, no imports).
// -------------------------------------------------------------------------
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
