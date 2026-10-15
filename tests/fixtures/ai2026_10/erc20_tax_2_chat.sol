// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BaseMemeToken
 * @notice ERC20 with configurable buy/sell taxes routed to a dev wallet.
 *         Self-contained — no imports. Deploy via Remix to Base.
 */
contract BaseMemeToken {
    // --- ERC20 metadata ---
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    // --- ERC20 state ---
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // --- Tax configuration ---
    // Basis points: 100 = 1%. Buy = 3% = 300. Sell = 7% = 700.
    uint256 public buyTaxBps = 300;
    uint256 public sellTaxBps = 700;
    uint256 public constant MAX_TAX_BPS = 2000; // hard cap at 20%

    address public devWallet;
    address public owner;

    // --- DEX pair tracking ---
    // Set this after creating the liquidity pool. Any transfer *to* the pair
    // is treated as a sell; any transfer *from* the pair is treated as a buy.
    address public pair;

    // --- Events ---
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event TaxesUpdated(uint256 buyTaxBps, uint256 sellTaxBps);
    event DevWalletUpdated(address indexed newDevWallet);
    event PairUpdated(address indexed newPair);

    // --- Modifiers ---
    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    /**
     * @param _name        Token name
     * @param _symbol      Token symbol
     * @param _supply      Total supply (in whole tokens — will be scaled by 1e18)
     * @param _devWallet   Address that receives collected taxes
     */
    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _supply,
        address _devWallet
    ) {
        require(_devWallet != address(0), "DEV_ZERO");
        name = _name;
        symbol = _symbol;
        owner = msg.sender;
        devWallet = _devWallet;

        // Mint entire supply to deployer
        uint256 supply = _supply * (10 ** uint256(decimals));
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    // ------------------------------------------------------------------
    // ERC20 standard functions
    // ------------------------------------------------------------------

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
            require(allowed >= amount, "INSUFFICIENT_ALLOWANCE");
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    // ------------------------------------------------------------------
    // Core transfer logic with tax
    // ------------------------------------------------------------------

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "TRANSFER_ZERO");
        require(balanceOf[from] >= amount, "INSUFFICIENT_BALANCE");

        uint256 taxAmount = 0;
        uint256 taxBps = 0;

        // Only apply tax if a pair is configured and this is a buy/sell.
        if (pair != address(0)) {
            if (from == pair) {
                taxBps = buyTaxBps;   // buying from the pool
            } else if (to == pair) {
                taxBps = sellTaxBps;  // selling into the pool
            }
        }

        if (taxBps > 0) {
            taxAmount = (amount * taxBps) / 10000;
        }

        uint256 netAmount = amount - taxAmount;

        balanceOf[from] -= amount;
        balanceOf[to] += netAmount;
        emit Transfer(from, to, netAmount);

        if (taxAmount > 0) {
            balanceOf[devWallet] += taxAmount;
            emit Transfer(from, devWallet, taxAmount);
        }
    }

    // ------------------------------------------------------------------
    // Owner-only configuration
    // ------------------------------------------------------------------

    /**
     * @notice Update buy/sell taxes. Values are in basis points (100 = 1%).
     *         Hard-capped at MAX_TAX_BPS (2000 = 20%).
     */
    function setTaxes(uint256 _buyTaxBps, uint256 _sellTaxBps) external onlyOwner {
        require(_buyTaxBps <= MAX_TAX_BPS, "BUY_TAX_TOO_HIGH");
        require(_sellTaxBps <= MAX_TAX_BPS, "SELL_TAX_TOO_HIGH");
        buyTaxBps = _buyTaxBps;
        sellTaxBps = _sellTaxBps;
        emit TaxesUpdated(_buyTaxBps, _sellTaxBps);
    }

    function setDevWallet(address _devWallet) external onlyOwner {
        require(_devWallet != address(0), "DEV_ZERO");
        devWallet = _devWallet;
        emit DevWalletUpdated(_devWallet);
    }

    /**
     * @notice Set the DEX pair address. Once set, transfers to/from this
     *         address are taxed. Set to address(0) to disable taxes.
     */
    function setPair(address _pair) external onlyOwner {
        pair = _pair;
        emit PairUpdated(_pair);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "OWNER_ZERO");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
