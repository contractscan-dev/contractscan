// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TimeLockSavings
 * @notice Users can deposit ETH and lock it until a chosen unlock date.
 *         Withdrawals are only allowed after the unlock time has passed.
 *         The owner has an emergency withdrawal function to rescue funds.
 */
contract TimeLockSavings {
    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    struct Deposit {
        uint256 amount;       // amount of ETH locked (in wei)
        uint256 unlockTime;   // unix timestamp when funds become withdrawable
        bool withdrawn;       // whether this deposit has already been withdrawn
    }

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    address public owner;

    /// @notice Each user can have multiple deposits (like different "buckets").
    mapping(address => Deposit[]) private deposits;

    /// @notice Total amount each user has locked (only counting active deposits).
    mapping(address => uint256) public lockedBalance;

    /// @notice Total ETH held by the contract (for quick emergency accounting).
    uint256 public totalLocked;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event Deposited(
        address indexed user,
        uint256 indexed depositId,
        uint256 amount,
        uint256 unlockTime
    );
    event Withdrawn(
        address indexed user,
        uint256 indexed depositId,
        uint256 amount
    );
    event EmergencyWithdrawn(address indexed owner, uint256 amount);

    // ---------------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor() {
        owner = msg.sender;
    }

    // ---------------------------------------------------------------------
    // External functions
    // ---------------------------------------------------------------------

    /**
     * @notice Lock ETH until `unlockTime` (unix timestamp).
     * @param unlockTime Must be greater than current block.timestamp.
     * @return depositId The id (index) of the new deposit for the caller.
     */
    function deposit(uint256 unlockTime) external payable returns (uint256 depositId) {
        require(msg.value > 0, "Must send ETH");
        require(unlockTime > block.timestamp, "Unlock time must be in the future");

        deposits[msg.sender].push(
            Deposit({
                amount: msg.value,
                unlockTime: unlockTime,
                withdrawn: false
            })
        );

        depositId = deposits[msg.sender].length - 1;

        lockedBalance[msg.sender] += msg.value;
        totalLocked += msg.value;

        emit Deposited(msg.sender, depositId, msg.value, unlockTime);
    }

    /**
     * @notice Withdraw a specific deposit after its unlock time.
     * @param depositId The id of the deposit to withdraw.
     */
    function withdraw(uint256 depositId) external {
        require(depositId < deposits[msg.sender].length, "Invalid deposit id");

        Deposit storage d = deposits[msg.sender][depositId];
        require(!d.withdrawn, "Already withdrawn");
        require(block.timestamp >= d.unlockTime, "Still locked");

        uint256 amount = d.amount;
        d.withdrawn = true;

        lockedBalance[msg.sender] -= amount;
        totalLocked -= amount;

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "ETH transfer failed");

        emit Withdrawn(msg.sender, depositId, amount);
    }

    /**
     * @notice Convenience: withdraw all deposits that are currently unlocked.
     */
    function withdrawAllUnlocked() external {
        Deposit[] storage userDeposits = deposits[msg.sender];
        uint256 totalAmount = 0;

        for (uint256 i = 0; i < userDeposits.length; i++) {
            Deposit storage d = userDeposits[i];
            if (!d.withdrawn && block.timestamp >= d.unlockTime) {
                totalAmount += d.amount;
                d.withdrawn = true;
                emit Withdrawn(msg.sender, i, d.amount);
            }
        }

        require(totalAmount > 0, "Nothing to withdraw");

        lockedBalance[msg.sender] -= totalAmount;
        totalLocked -= totalAmount;

        (bool ok, ) = payable(msg.sender).call{value: totalAmount}("");
        require(ok, "ETH transfer failed");
    }

    /**
     * @notice Emergency: owner can withdraw the entire contract balance.
     * @dev Should only be used if something is seriously wrong.
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No balance");

        totalLocked = 0;

        (bool ok, ) = payable(owner).call{value: balance}("");
        require(ok, "ETH transfer failed");

        emit EmergencyWithdrawn(owner, balance);
    }

    /**
     * @notice Transfer contract ownership.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // ---------------------------------------------------------------------
    // View functions
    // ---------------------------------------------------------------------

    /**
     * @notice Get a specific deposit for a user.
     */
    function getDeposit(address user, uint256 depositId)
        external
        view
        returns (uint256 amount, uint256 unlockTime, bool withdrawn)
    {
        require(depositId < deposits[user].length, "Invalid deposit id");
        Deposit storage d = deposits[user][depositId];
        return (d.amount, d.unlockTime, d.withdrawn);
    }

    /**
     * @notice Get all deposits for a user.
     */
    function getUserDeposits(address user)
        external
        view
        returns (Deposit[] memory)
    {
        return deposits[user];
    }

    /**
     * @notice Number of deposits a user has created.
     */
    function getUserDepositCount(address user) external view returns (uint256) {
        return deposits[user].length;
    }

    /**
     * @notice Contract ETH balance.
     */
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // ---------------------------------------------------------------------
    // Safety
    // ---------------------------------------------------------------------

    /// @dev Reject plain ETH transfers with no data (must use `deposit`).
    receive() external payable {
        revert("Use deposit()");
    }

    fallback() external payable {
        revert("Use deposit()");
    }
}
