// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* =========================================================================
   Minimal ERC20 interface — declared inline so the file needs no imports
   ========================================================================= */
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/* =========================================================================
   TokenStaking
   -------------------------------------------------------------------------
   - Users stake ERC20 tokens.
   - They earn 20% APR (fixed) in the SAME token, accrued per second.
   - Unstake anytime, principal is never locked.
   - Claim rewards whenever they want.
   - Rewards come from a pre-funded pool (fundRewards) so staked principal
     is never used to pay rewards.
   ========================================================================= */
contract TokenStaking {
    /* ----------------------------- Constants ----------------------------- */

    /// @dev 20% APR as "reward tokens per staked token per second", scaled by 1e18.
    ///      0.20e18 / 31,536,000s (365 days) = 6,341,958,396
    uint256 public constant REWARD_RATE_PER_SECOND = 6_341_958_396;

    uint256 private constant PRECISION = 1e18;

    /* ------------------------------- Storage ------------------------------ */

    IERC20 public immutable stakingToken;
    address public owner;

    uint256 public totalStaked;           // sum of all user stakes
    uint256 public rewardPerTokenStored;  // accumulator, scaled by 1e18
    uint256 public lastUpdateTime;        // last time the accumulator was updated
    uint256 public rewardReserve;         // tokens set aside to pay rewards

    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public pendingRewards; // accrued, not yet claimed

    /* ------------------------------- Events ------------------------------- */

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 amount);
    event RewardsFunded(address indexed from, uint256 amount);
    event ExcessWithdrawn(address indexed to, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /* ------------------------------ Modifiers ----------------------------- */

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    uint256 private _locked = 1;
    modifier nonReentrant() {
        require(_locked == 1, "Reentrant call");
        _locked = 2;
        _;
        _locked = 1;
    }

    /* ----------------------------- Constructor ---------------------------- */

    constructor(address _stakingToken) {
        require(_stakingToken != address(0), "Zero token address");
        stakingToken = IERC20(_stakingToken);
        owner = msg.sender;
        lastUpdateTime = block.timestamp;
    }

    /* --------------------------- Internal helpers ------------------------- */

    /// @dev Advances the global reward accumulator up to `block.timestamp`
    ///      and, if `account != 0`, checkpoints that account's rewards.
    function _updateRewards(address account) internal {
        uint256 elapsed = block.timestamp - lastUpdateTime;

        if (elapsed > 0) {
            // No stakers => no rewards accrue (time still advances so no
            // retroactive rewards are handed out when the next stake comes in).
            if (totalStaked > 0) {
                rewardPerTokenStored += elapsed * REWARD_RATE_PER_SECOND;
            }
            lastUpdateTime = block.timestamp;
        }

        if (account != address(0)) {
            pendingRewards[account] = _earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
    }

    /// @dev Rewards this account has earned but not yet claimed.
    function _earned(address account) internal view returns (uint256) {
        return
            pendingRewards[account] +
            (stakedBalance[account] * (rewardPerTokenStored - userRewardPerTokenPaid[account])) /
            PRECISION;
    }

    /* -------------------------------- Views ------------------------------- */

    /// @notice Total rewards `account` can claim right now.
    function earned(address account) public view returns (uint256) {
        uint256 stored = rewardPerTokenStored;
        uint256 elapsed = block.timestamp - lastUpdateTime;

        if (elapsed > 0 && totalStaked > 0) {
            stored += elapsed * REWARD_RATE_PER_SECOND;
        }

        return
            pendingRewards[account] +
            (stakedBalance[account] * (stored - userRewardPerTokenPaid[account])) / PRECISION;
    }

    /// @notice Tokens currently set aside to pay rewards.
    function rewardsAvailable() external view returns (uint256) {
        return rewardReserve;
    }

    /// @notice Annualised rate, in percent (here: 20).
    function aprPercent() external pure returns (uint256) {
        // REWARD_RATE_PER_SECOND * SECONDS_PER_YEAR / 1e18 * 100
        return (REWARD_RATE_PER_SECOND * 365 days * 100) / PRECISION;
    }

    /* ------------------------------ User actions -------------------------- */

    /// @notice Stake `amount` tokens. Caller must have approved this contract.
    function stake(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount is 0");

        _updateRewards(msg.sender);

        totalStaked += amount;
        stakedBalance[msg.sender] += amount;

        require(stakingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        emit Staked(msg.sender, amount);
    }

    /// @notice Withdraw `amount` of staked principal. Rewards keep accruing on
    ///         the remaining stake. Pending rewards are NOT auto-claimed.
    function unstake(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount is 0");
        require(amount <= stakedBalance[msg.sender], "Insufficient staked balance");

        _updateRewards(msg.sender);

        totalStaked -= amount;
        stakedBalance[msg.sender] -= amount;

        require(stakingToken.transfer(msg.sender, amount), "Transfer failed");

        emit Unstaked(msg.sender, amount);
    }

    /// @notice Claim all rewards accrued so far.
    function claim() public nonReentrant {
        _updateRewards(msg.sender);

        uint256 reward = pendingRewards[msg.sender];
        if (reward == 0) return;

        require(reward <= rewardReserve, "Reward pool not funded enough");

        pendingRewards[msg.sender] = 0;
        rewardReserve -= reward;

        require(stakingToken.transfer(msg.sender, reward), "Transfer failed");

        emit RewardPaid(msg.sender, reward);
    }

    /// @notice Convenience: unstake everything AND claim rewards.
    function exit() external nonReentrant {
        uint256 amount = stakedBalance[msg.sender];

        if (amount > 0) {
            _updateRewards(msg.sender);
            totalStaked -= amount;
            stakedBalance[msg.sender] -= amount;
            require(stakingToken.transfer(msg.sender, amount), "Transfer failed");
            emit Unstaked(msg.sender, amount);
        }

        claim();
    }

    /* ----------------------------- Reward funding ------------------------- */

    /// @notice Anyone can top up the reward pool (typically the project owner).
    ///         Caller must have approved this contract for `amount`.
    function fundRewards(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount is 0");

        rewardReserve += amount;
        require(stakingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        emit RewardsFunded(msg.sender, amount);
    }

    /* -------------------------------- Admin ------------------------------- */

    /// @notice Withdraw tokens that are neither staked nor reserved for rewards
    ///         (e.g. accidentally sent to this contract).
    function withdrawExcess(uint256 amount) external onlyOwner nonReentrant {
        uint256 excess = stakingToken.balanceOf(address(this)) - totalStaked - rewardReserve;
        require(amount <= excess, "Exceeds excess balance");
        require(stakingToken.transfer(owner, amount), "Transfer failed");
        emit ExcessWithdrawn(owner, amount);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Move reward tokens from the reserve back to the owner. Cannot
    ///         touch staked principal. Claimers may then be unable to claim
    ///         until you re-fund — use with care.
    function withdrawUnusedRewards(uint256 amount) external onlyOwner nonReentrant {
        require(amount <= rewardReserve, "Exceeds reward reserve");
        rewardReserve -= amount;
        require(stakingToken.transfer(owner, amount), "Transfer failed");
        emit ExcessWithdrawn(owner, amount);
    }
}

/* =========================================================================
   OPTIONAL TEST TOKEN — delete this whole contract in production.
   Deploy it, mint yourself tokens, then use it to try the staking contract
   inside Remix.
   ========================================================================= */
contract TestERC20 is IERC20 {
    string public name = "Test Token";
    string public symbol = "TEST";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "Allowance too low");
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        require(to != address(0), "Zero address");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "Zero address");
        require(balanceOf[from] >= amount, "Balance too low");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
