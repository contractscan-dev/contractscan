// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MOON Token
 * @notice ERC20 token with 1B supply and 5% tax on buys/sells sent to marketing wallet.
 *         Owner can exclude wallets from tax and update the marketing wallet.
 */
contract MOON {
    // ============ ERC20 State ============
    string public constant name = "MOON";
    string public constant symbol = "MOON";
    uint8  public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ============ Tax / Ownership State ============
    address public owner;
    address public marketingWallet;

    uint256 public constant TAX_BPS = 500; // 5% = 500 basis points
    uint256 public constant BPS_DENOMINATOR = 10_000;

    // Wallets excluded from tax (e.g., owner, marketing wallet, router, presale, etc.)
    mapping(address => bool) public isExcludedFromTax;

    // ============ Events ============
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event MarketingWalletUpdated(address indexed previousWallet, address indexed newWallet);
    event ExcludedFromTaxUpdated(address indexed account, bool excluded);

    // ============ Modifiers ============
    modifier onlyOwner() {
        require(msg.sender == owner, "MOON: caller is not the owner");
        _;
    }

    // ============ Constructor ============
    constructor(address _marketingWallet) {
        require(_marketingWallet != address(0), "MOON: marketing wallet is zero address");

        owner = msg.sender;
        marketingWallet = _marketingWallet;

        // Exclude owner and marketing wallet from tax by default
        isExcludedFromTax[msg.sender] = true;
        isExcludedFromTax[_marketingWallet] = true;
        isExcludedFromTax[address(this)] = true;

        // Mint 1 billion tokens (18 decimals) to the deployer
        totalSupply = 1_000_000_000 * (10 ** uint256(decimals));
        balanceOf[msg.sender] = totalSupply;

        emit Transfer(address(0), msg.sender, totalSupply);
        emit MarketingWalletUpdated(address(0), _marketingWallet);
        emit ExcludedFromTaxUpdated(msg.sender, true);
        emit ExcludedFromTaxUpdated(_marketingWallet, true);
    }

    // ============ ERC20 Core ============
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "MOON: insufficient allowance");
            unchecked {
                allowance[from][msg.sender] = allowed - amount;
            }
        }
        _transfer(from, to, amount);
        return true;
    }

    // ============ Internal Transfer Logic with Tax ============
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "MOON: transfer from zero address");
        require(to != address(0), "MOON: transfer to zero address");
        require(balanceOf[from] >= amount, "MOON: insufficient balance");

        uint256 taxAmount = 0;

        // Apply tax only if neither party is excluded
        if (!isExcludedFromTax[from] && !isExcludedFromTax[to]) {
            taxAmount = (amount * TAX_BPS) / BPS_DENOMINATOR;
        }

        uint256 sendAmount = amount - taxAmount;

        // Debit sender
        unchecked {
            balanceOf[from] -= amount;
        }

        // Credit recipient
        balanceOf[to] += sendAmount;

        // Credit marketing wallet with tax
        if (taxAmount > 0) {
            balanceOf[marketingWallet] += taxAmount;
            emit Transfer(from, marketingWallet, taxAmount);
        }

        emit Transfer(from, to, sendAmount);
    }

    // ============ Owner Functions ============
    function setExcludedFromTax(address account, bool excluded) external onlyOwner {
        require(account != address(0), "MOON: zero address");
        isExcludedFromTax[account] = excluded;
        emit ExcludedFromTaxUpdated(account, excluded);
    }

    function setMarketingWallet(address newWallet) external onlyOwner {
        require(newWallet != address(0), "MOON: marketing wallet is zero address");
        address old = marketingWallet;
        marketingWallet = newWallet;
        emit MarketingWalletUpdated(old, newWallet);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "MOON: new owner is zero address");
        address old = owner;
        owner = newOwner;
        emit OwnershipTransferred(old, newOwner);
    }
}
