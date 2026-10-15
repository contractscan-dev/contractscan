// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FreelanceEscrow
 * @notice An escrow contract for freelance jobs where:
 *         - The client deposits ETH for the job.
 *         - The freelancer gets paid when the client approves the work.
 *         - An arbiter can resolve disputes (pay freelancer or refund client).
 */
contract FreelanceEscrow {
    // --------------------------------------------------------------------
    // Types
    // --------------------------------------------------------------------

    enum Status {
        AWAITING_DEPOSIT, // created, no funds yet
        FUNDED,           // client deposited, freelancer can work
        COMPLETED,        // client approved, freelancer paid
        REFUNDED,         // arbiter refunded client
        DISPUTED          // client opened a dispute
    }

    // --------------------------------------------------------------------
    // State
    // --------------------------------------------------------------------

    address public immutable client;
    address public immutable freelancer;
    address public immutable arbiter;

    uint256 public immutable amount;
    string  public  jobDescription;

    Status  public status;
    uint256 public createdAt;
    uint256 public disputeOpenedAt;

    // --------------------------------------------------------------------
    // Events
    // --------------------------------------------------------------------

    event Deposited(address indexed by, uint256 amount);
    event WorkApproved(address indexed by, address indexed freelancer, uint256 amount);
    event DisputeOpened(address indexed by, string reason);
    event DisputeResolved(address indexed arbiter, Status outcome, uint256 amount);
    event Refunded(address indexed by, address indexed client, uint256 amount);

    // --------------------------------------------------------------------
    // Modifiers
    // --------------------------------------------------------------------

    modifier onlyClient() {
        require(msg.sender == client, "Only client");
        _;
    }

    modifier onlyFreelancer() {
        require(msg.sender == freelancer, "Only freelancer");
        _;
    }

    modifier onlyArbiter() {
        require(msg.sender == arbiter, "Only arbiter");
        _;
    }

    modifier inStatus(Status _status) {
        require(status == _status, "Invalid status");
        _;
    }

    // --------------------------------------------------------------------
    // Constructor
    // --------------------------------------------------------------------

    /**
     * @param _freelancer   Address that will perform the work.
     * @param _arbiter      Address that resolves disputes (should differ from client & freelancer).
     * @param _amount       Exact ETH amount the client must deposit (in wei).
     * @param _jobDescription Short description of the job.
     */
    constructor(
        address _freelancer,
        address _arbiter,
        uint256 _amount,
        string memory _jobDescription
    ) {
        require(_freelancer != address(0), "Freelancer required");
        require(_arbiter   != address(0), "Arbiter required");
        require(_freelancer != msg.sender, "Client cannot be freelancer");
        require(_arbiter    != msg.sender, "Client cannot be arbiter");
        require(_arbiter    != _freelancer, "Arbiter cannot be freelancer");
        require(_amount > 0, "Amount must be > 0");

        client        = msg.sender;
        freelancer    = _freelancer;
        arbiter       = _arbiter;
        amount        = _amount;
        jobDescription = _jobDescription;
        createdAt     = block.timestamp;
        status        = Status.AWAITING_DEPOSIT;
    }

    // --------------------------------------------------------------------
    // Client flow
    // --------------------------------------------------------------------

    /**
     * @notice Client deposits exactly `amount` ETH to fund the escrow.
     */
    function deposit() external payable onlyClient inStatus(Status.AWAITING_DEPOSIT) {
        require(msg.value == amount, "Must send exact amount");
        status = Status.FUNDED;
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Client approves the freelancer's work and releases payment.
     */
    function approveWork() external onlyClient inStatus(Status.FUNDED) {
        status = Status.COMPLETED;
        uint256 payout = address(this).balance;
        (bool ok, ) = payable(freelancer).call{value: payout}("");
        require(ok, "Payment failed");
        emit WorkApproved(msg.sender, freelancer, payout);
    }

    /**
     * @notice Client opens a dispute; funds remain in escrow until the arbiter resolves it.
     * @param reason Short text describing the issue.
     */
    function openDispute(string calldata reason)
        external
        onlyClient
        inStatus(Status.FUNDED)
    {
        status = Status.DISPUTED;
        disputeOpenedAt = block.timestamp;
        emit DisputeOpened(msg.sender, reason);
    }

    // --------------------------------------------------------------------
    // Arbiter flow
    // --------------------------------------------------------------------

    /**
     * @notice Arbiter resolves the dispute by releasing funds to the freelancer.
     */
    function resolveToFreelancer() external onlyArbiter inStatus(Status.DISPUTED) {
        status = Status.COMPLETED;
        uint256 payout = address(this).balance;
        (bool ok, ) = payable(freelancer).call{value: payout}("");
        require(ok, "Payment failed");
        emit DisputeResolved(msg.sender, Status.COMPLETED, payout);
    }

    /**
     * @notice Arbiter resolves the dispute by refunding the client.
     */
    function resolveToClient() external onlyArbiter inStatus(Status.DISPUTED) {
        status = Status.REFUNDED;
        uint256 refund = address(this).balance;
        (bool ok, ) = payable(client).call{value: refund}("");
        require(ok, "Refund failed");
        emit DisputeResolved(msg.sender, Status.REFUNDED, refund);
    }

    // --------------------------------------------------------------------
    // Voluntary refund by client (bonus, before any dispute)
    // --------------------------------------------------------------------

    /**
     * @notice Client voluntarily refunds themselves (e.g., freelancer vanished).
     *         Only works while FUNDED. Not available once a dispute is open,
     *         so the freelancer's protection is preserved.
     */
    function voluntaryRefund() external onlyClient inStatus(Status.FUNDED) {
        status = Status.REFUNDED;
        uint256 refund = address(this).balance;
        (bool ok, ) = payable(client).call{value: refund}("");
        require(ok, "Refund failed");
        emit Refunded(msg.sender, client, refund);
    }

    // --------------------------------------------------------------------
    // View helpers
    // --------------------------------------------------------------------

    function getSummary()
        external
        view
        returns (
            address _client,
            address _freelancer,
            address _arbiter,
            uint256 _amount,
            uint256 _balance,
            Status  _status,
            string memory _jobDescription
        )
    {
        return (client, freelancer, arbiter, amount, address(this).balance, status, jobDescription);
    }
}
