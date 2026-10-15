// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  Minimal Uniswap-V2-style AMM for ONE ETH / ERC20 pair
 * @notice Constant product (x * y = k) with a 0.3% swap fee.
 *         The pair contract itself is the LP token (ERC20).
 *         Reserves are derived from the contract's balances, so the
 *         pool can never get out of sync.
 *
 *  NOTE: assumes a standard ERC20 (no fee-on-transfer / rebasing / ERC777 hooks).
 */

/* -------------------------------------------------------------------------- */
/*                            Minimal ERC20 interface                         */
/* -------------------------------------------------------------------------- */

interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/* -------------------------------------------------------------------------- */
/*                                  The Pair                                  */
/* -------------------------------------------------------------------------- */

contract ETHTokenPair {
    /* ----------------------------- LP token (ERC20) ----------------------------- */

    string public constant name = "AMM LP Token";
    string public constant symbol = "AMM-LP";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /* --------------------------------- Events --------------------------------- */

    event Mint(address indexed sender, uint256 ethAmount, uint256 tokenAmount, uint256 liquidity);
    event Burn(address indexed sender, uint256 ethAmount, uint256 tokenAmount, uint256 liquidity);
    event Swap(address indexed sender, bool ethIn, uint256 amountIn, uint256 amountOut);

    /* -------------------------------- Constants ------------------------------- */

    /// @dev Permanently locked on the first deposit (Uniswap V2 style).
    uint256 public constant MINIMUM_LIQUIDITY = 1_000;

    /// @dev 0.3% fee -> keep 997/1000 of the input amount.
    uint256 public constant FEE_NUMERATOR = 997;
    uint256 public constant FEE_DENOMINATOR = 1000;

    /* ---------------------------------- State --------------------------------- */

    IERC20 public immutable TOKEN;

    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "REENTRANCY");
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor(address tokenAddress) {
        require(tokenAddress != address(0), "ZERO_ADDRESS");
        require(tokenAddress.code.length > 0, "NOT_A_CONTRACT");
        TOKEN = IERC20(tokenAddress);
    }

    /* --------------------------------- Views ---------------------------------- */

    /// @notice Current reserves, read straight from the contract balances.
    function getReserves() public view returns (uint256 ethReserve, uint256 tokenReserve) {
        ethReserve = address(this).balance;
        tokenReserve = TOKEN.balanceOf(address(this));
    }

    /// @notice Constant-product output with 0.3% fee (Uniswap V2 formula).
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public
        pure
        returns (uint256 amountOut)
    {
        require(amountIn > 0, "INSUFFICIENT_INPUT_AMOUNT");
        require(reserveIn > 0 && reserveOut > 0, "INSUFFICIENT_LIQUIDITY");

        uint256 amountInWithFee = amountIn * FEE_NUMERATOR;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * FEE_DENOMINATOR + amountInWithFee;

        amountOut = numerator / denominator;
    }

    /// @notice Convenience helper: how many tokens for `ethIn`?
    function quoteETHForToken(uint256 ethIn) external view returns (uint256) {
        (uint256 ethReserve, uint256 tokenReserve) = getReserves();
        return getAmountOut(ethIn, ethReserve, tokenReserve);
    }

    /// @notice Convenience helper: how much ETH for `tokenIn`?
    function quoteTokenForETH(uint256 tokenIn) external view returns (uint256) {
        (uint256 ethReserve, uint256 tokenReserve) = getReserves();
        return getAmountOut(tokenIn, tokenReserve, ethReserve);
    }

    /* ------------------------------ Add liquidity ----------------------------- */

    /**
     * @notice Deposit ETH (msg.value) + `tokenAmount` tokens, receive LP tokens.
     * @dev    The pair must be approved to spend `tokenAmount` beforehand.
     */
    function addLiquidity(uint256 tokenAmount)
        external
        payable
        nonReentrant
        returns (uint256 liquidity)
    {
        uint256 ethAmount = msg.value;
        require(ethAmount > 0, "ZERO_ETH");
        require(tokenAmount > 0, "ZERO_TOKEN");

        // Reserves *before* this deposit.
        uint256 ethReserve = address(this).balance - ethAmount;
        uint256 tokenReserve = TOKEN.balanceOf(address(this));

        // Pull the tokens and measure what actually arrived.
        require(TOKEN.transferFrom(msg.sender, address(this), tokenAmount), "TRANSFER_FROM_FAILED");
        uint256 tokenReceived = TOKEN.balanceOf(address(this)) - tokenReserve;
        require(tokenReceived > 0, "NO_TOKENS_RECEIVED");

        uint256 supply = totalSupply;

        if (supply == 0) {
            // First deposit sets the price: liquidity = sqrt(eth * token).
            liquidity = _sqrt(ethAmount * tokenReceived);
            require(liquidity > MINIMUM_LIQUIDITY, "INSUFFICIENT_LIQUIDITY");

            // Lock a tiny amount forever so the pool can never be fully drained.
            _mint(address(0), MINIMUM_LIQUIDITY);
            liquidity -= MINIMUM_LIQUIDITY;
        } else {
            // Mint proportionally to the smaller side.
            uint256 liquidityETH = (ethAmount * supply) / ethReserve;
            uint256 liquidityToken = (tokenReceived * supply) / tokenReserve;
            liquidity = liquidityETH < liquidityToken ? liquidityETH : liquidityToken;
            require(liquidity > 0, "INSUFFICIENT_LIQUIDITY");
        }

        _mint(msg.sender, liquidity);
        emit Mint(msg.sender, ethAmount, tokenReceived, liquidity);
    }

    /* ----------------------------- Remove liquidity --------------------------- */

    /**
     * @notice Burn `liquidity` LP tokens and receive your share of ETH + tokens.
     */
    function removeLiquidity(uint256 liquidity)
        external
        nonReentrant
        returns (uint256 ethAmount, uint256 tokenAmount)
    {
        require(liquidity > 0, "ZERO_LIQUIDITY");

        uint256 supply = totalSupply;
        uint256 ethReserve = address(this).balance;
        uint256 tokenReserve = TOKEN.balanceOf(address(this));

        ethAmount = (liquidity * ethReserve) / supply;
        tokenAmount = (liquidity * tokenReserve) / supply;
        require(ethAmount > 0 && tokenAmount > 0, "INSUFFICIENT_LIQUIDITY_BURNED");

        _burn(msg.sender, liquidity);

        require(TOKEN.transfer(msg.sender, tokenAmount), "TOKEN_TRANSFER_FAILED");
        (bool okETH, ) = msg.sender.call{value: ethAmount}("");
        require(okETH, "ETH_TRANSFER_FAILED");

        emit Burn(msg.sender, ethAmount, tokenAmount, liquidity);
    }

    /* --------------------------------- Swaps ---------------------------------- */

    /**
     * @notice Swap ETH (msg.value) for tokens.
     * @param  minTokensOut Slippage protection (use 0 to disable).
     */
    function swapETHForToken(uint256 minTokensOut)
        external
        payable
        nonReentrant
        returns (uint256 tokensOut)
    {
        uint256 ethIn = msg.value;
        require(ethIn > 0, "ZERO_INPUT");

        uint256 ethReserve = address(this).balance - ethIn;
        uint256 tokenReserve = TOKEN.balanceOf(address(this));

        tokensOut = getAmountOut(ethIn, ethReserve, tokenReserve);
        require(tokensOut >= minTokensOut, "SLIPPAGE");
        require(tokensOut < tokenReserve, "INSUFFICIENT_LIQUIDITY");

        require(TOKEN.transfer(msg.sender, tokensOut), "TOKEN_TRANSFER_FAILED");
        emit Swap(msg.sender, true, ethIn, tokensOut);
    }

    /**
     * @notice Swap `tokensIn` tokens for ETH.
     * @param  minEthOut Slippage protection (use 0 to disable).
     * @dev    Approve the pair for `tokensIn` beforehand.
     */
    function swapTokenForETH(uint256 tokensIn, uint256 minEthOut)
        external
        nonReentrant
        returns (uint256 ethOut)
    {
        require(tokensIn > 0, "ZERO_INPUT");

        uint256 tokenReserve = TOKEN.balanceOf(address(this));
        require(TOKEN.transferFrom(msg.sender, address(this), tokensIn), "TRANSFER_FROM_FAILED");

        // Measure what actually arrived.
        uint256 tokensInActual = TOKEN.balanceOf(address(this)) - tokenReserve;
        require(tokensInActual > 0, "NO_TOKENS_RECEIVED");

        uint256 ethReserve = address(this).balance;

        ethOut = getAmountOut(tokensInActual, tokenReserve, ethReserve);
        require(ethOut >= minEthOut, "SLIPPAGE");
        require(ethOut < ethReserve, "INSUFFICIENT_LIQUIDITY");

        (bool okETH, ) = msg.sender.call{value: ethOut}("");
        require(okETH, "ETH_TRANSFER_FAILED");

        emit Swap(msg.sender, false, tokensInActual, ethOut);
    }

    /* ------------------------------ LP token logic ---------------------------- */

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "ALLOWANCE");
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "TRANSFER_TO_ZERO");
        uint256 bal = balanceOf[from];
        require(bal >= value, "BALANCE");
        unchecked {
            balanceOf[from] = bal - value;
        }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) internal {
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function _burn(address from, uint256 value) internal {
        uint256 bal = balanceOf[from];
        require(bal >= value, "BALANCE");
        unchecked {
            balanceOf[from] = bal - value;
        }
        totalSupply -= value;
        emit Transfer(from, address(0), value);
    }

    /* -------------------------------- Helpers --------------------------------- */

    /// @dev Babylonian square root (used only for the initial LP mint).
    function _sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
        // if y == 0 -> z == 0
    }
}

/* -------------------------------------------------------------------------- */
/*                Test ERC20 — only for trying things out in Remix            */
/* -------------------------------------------------------------------------- */

contract TestToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint256 _supplyInWholeTokens) {
        name = _name;
        symbol = _symbol;
        _mint(msg.sender, _supplyInWholeTokens * 1e18);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= value, "ALLOWANCE");
            allowance[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function mint(address to, uint256 value) external {
        _mint(to, value);
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "ZERO_ADDRESS");
        uint256 bal = balanceOf[from];
        require(bal >= value, "BALANCE");
        unchecked {
            balanceOf[from] = bal - value;
        }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) internal {
        require(to != address(0), "ZERO_ADDRESS");
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }
}
