// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal ERC20 interface
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
    function name() external view returns (string memory);
}

// Minimal LP token interface
interface ILPToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/**
 * @title MinimalLP - A minimal ERC20 LP token, only mintable/burnable by the AMM.
 */
contract MinimalLP {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public immutable amm;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        amm = msg.sender;
    }

    modifier onlyAMM() {
        require(msg.sender == amm, "only AMM");
        _;
    }

    function mint(address to, uint256 amount) external onlyAMM {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external onlyAMM {
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero addr");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/**
 * @title TokenSwap
 * @notice Constant-product AMM for a single ERC20/ETH pair (Uniswap V2 style).
 *         0.3% fee on swaps.
 */
contract TokenSwap {
    uint256 public constant FEE_NUMERATOR = 3;         // 0.3%
    uint256 public constant FEE_DENOMINATOR = 1000;
    uint256 public constant MINIMUM_LIQUIDITY = 1000;  // locked forever on first mint

    IERC20 public immutable token;
    MinimalLP public immutable lpToken;

    uint256 public reserveETH;
    uint256 public reserveToken;

    event Mint(address indexed to, uint256 amountETH, uint256 amountToken, uint256 liquidity);
    event Burn(address indexed from, uint256 amountETH, uint256 amountToken, uint256 liquidity);
    event Swap(
        address indexed sender,
        uint256 amountETHIn,
        uint256 amountTokenIn,
        uint256 amountETHOut,
        uint256 amountTokenOut,
        address indexed to
    );
    event Sync(uint256 reserveETH, uint256 reserveToken);

    constructor(address _token) {
        require(_token != address(0), "token=0");
        token = IERC20(_token);
        string memory lpSymbol = string(abi.encodePacked("LP-", token.symbol()));
        lpToken = new MinimalLP("AMM LP Token", lpSymbol);
    }

    // ------------------------------------------------------------------
    // Liquidity
    // ------------------------------------------------------------------

    /**
     * @notice Add liquidity. Send ETH with this call; the contract will pull
     *         `amountTokenDesired` from the caller (must be approved).
     * @param amountTokenDesired Desired tokens to add.
     * @param amountTokenMin     Minimum tokens to add (slippage on tokenIn ratio).
     * @param amountETHMin       Minimum ETH to add (slippage on ETH ratio).
     */
    function addLiquidity(
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin
    ) external payable returns (uint256 liquidity) {
        uint256 amountETH = msg.value;
        require(amountETH > 0 && amountTokenDesired > 0, "amounts=0");

        uint256 _reserveETH = reserveETH;
        uint256 _reserveToken = reserveToken;

        uint256 amountToken = amountTokenDesired;
        uint256 amountETHUsed = amountETH;

        if (_reserveETH == 0 && _reserveToken == 0) {
            // Initial deposit: use provided amounts directly.
        } else {
            // Compute optimal token amount given ETH provided (keep ratio).
            uint256 tokenOptimal = (amountETH * _reserveToken) / _reserveETH;
            if (tokenOptimal <= amountTokenDesired) {
                amountToken = tokenOptimal;
                amountETHUsed = amountETH;
            } else {
                uint256 ethOptimal = (amountTokenDesired * _reserveETH) / _reserveToken;
                require(ethOptimal <= amountETH, "excess ETH");
                amountToken = amountTokenDesired;
                amountETHUsed = ethOptimal;
            }
        }

        require(amountToken >= amountTokenMin, "token slippage");
        require(amountETHUsed >= amountETHMin, "eth slippage");

        // Pull tokens from sender.
        _safeTransferFrom(address(token), msg.sender, address(this), amountToken);

        // Mint LP.
        uint256 _totalSupply = lpToken.totalSupply();
        if (_totalSupply == 0) {
            liquidity = _sqrt(amountETHUsed * amountToken) - MINIMUM_LIQUIDITY;
            lpToken.mint(address(0xdead), MINIMUM_LIQUIDITY);
        } else {
            uint256 liqETH = (amountETHUsed * _totalSupply) / _reserveETH;
            uint256 liqToken = (amountToken * _totalSupply) / _reserveToken;
            liquidity = liqETH < liqToken ? liqETH : liqToken;
        }
        require(liquidity > 0, "liquidity=0");
        lpToken.mint(msg.sender, liquidity);

        // Refund unused ETH if any.
        if (amountETH > amountETHUsed) {
            _safeTransferETH(msg.sender, amountETH - amountETHUsed);
        }

        _update();

        emit Mint(msg.sender, amountETHUsed, amountToken, liquidity);
    }

    /**
     * @notice Remove liquidity. LP tokens are burned; ETH + tokens sent back.
     * @param liquidity       LP tokens to burn (must be approved).
     * @param amountTokenMin  Min tokens to receive.
     * @param amountETHMin    Min ETH to receive.
     */
    function removeLiquidity(
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin
    ) external returns (uint256 amountETH, uint256 amountToken) {
        require(liquidity > 0, "liquidity=0");

        // Pull LP tokens from sender, burn them.
        require(lpToken.transferFrom(msg.sender, address(this), liquidity), "lp transferFrom");
        lpToken.burn(address(this), liquidity);

        uint256 _totalSupply = lpToken.totalSupply(); // after burn
        uint256 _reserveETH = reserveETH;
        uint256 _reserveToken = reserveToken;

        amountETH = (liquidity * _reserveETH) / (_totalSupply + liquidity);
        amountToken = (liquidity * _reserveToken) / (_totalSupply + liquidity);

        // (Recompute using actual pre-burn supply = current + liquidity)
        // Actually, lpToken.totalSupply() has already been reduced; add back:
        // Simpler: use the formula with the current reserves and the pre-burn total supply.
        uint256 totalSupplyBefore = _totalSupply + liquidity;
        amountETH = (liquidity * _reserveETH) / totalSupplyBefore;
        amountToken = (liquidity * _reserveToken) / totalSupplyBefore;

        require(amountETH >= amountETHMin, "eth slippage");
        require(amountToken >= amountTokenMin, "token slippage");
        require(amountETH > 0 && amountToken > 0, "amounts=0");

        _safeTransfer(address(token), msg.sender, amountToken);
        _safeTransferETH(msg.sender, amountETH);

        _update();

        emit Burn(msg.sender, amountETH, amountToken, liquidity);
    }

    // ------------------------------------------------------------------
    // Swaps
    // ------------------------------------------------------------------

    /**
     * @notice Swap exact ETH for tokens.
     */
    function swapExactETHForTokens(uint256 amountTokenMin, address to)
        external
        payable
        returns (uint256 amountTokenOut)
    {
        require(msg.value > 0, "eth=0");
        require(to != address(0), "to=0");

        uint256 amountInWithFee = msg.value * (FEE_DENOMINATOR - FEE_NUMERATOR);
        amountTokenOut = (amountInWithFee * reserveToken) / (reserveETH * FEE_DENOMINATOR + amountInWithFee);
        require(amountTokenOut >= amountTokenMin, "slippage");
        require(amountTokenOut < reserveToken, "insufficient liquidity");

        _safeTransfer(address(token), to, amountTokenOut);
        _update();

        emit Swap(msg.sender, msg.value, 0, 0, amountTokenOut, to);
    }

    /**
     * @notice Swap exact tokens for ETH.
     */
    function swapExactTokensForETH(
        uint256 amountTokenIn,
        uint256 amountETHMin,
        address to
    ) external returns (uint256 amountETHOut) {
        require(amountTokenIn > 0, "amount=0");
        require(to != address(0), "to=0");

        _safeTransferFrom(address(token), msg.sender, address(this), amountTokenIn);

        uint256 amountInWithFee = amountTokenIn * (FEE_DENOMINATOR - FEE_NUMERATOR);
        amountETHOut = (amountInWithFee * reserveETH) / (reserveToken * FEE_DENOMINATOR + amountInWithFee);
        require(amountETHOut >= amountETHMin, "slippage");
        require(amountETHOut < reserveETH, "insufficient liquidity");

        _safeTransferETH(to, amountETHOut);
        _update();

        emit Swap(msg.sender, 0, amountTokenIn, amountETHOut, 0, to);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _update() internal {
        reserveETH = address(this).balance;
        reserveToken = token.balanceOf(address(this));
        emit Sync(reserveETH, reserveToken);
    }

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
    }

    function _safeTransfer(address _token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = _token.call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function _safeTransferFrom(address _token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = _token.call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transferFrom failed");
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "eth transfer failed");
    }

    // Accept ETH (for swaps/adds via direct send not expected, but keep safe).
    receive() external payable {
        // Only allow ETH from WETH-style unwrapping; here we ignore.
        // Reserves are tracked via sync.
    }
}
