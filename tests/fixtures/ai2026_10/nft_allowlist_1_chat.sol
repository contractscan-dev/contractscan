// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NFTMint
 * @notice 5555 supply, allowlist mint (0.05 ETH, merkle), public mint (0.08 ETH, max 3/wallet).
 *         Uses ERC721A-style batch minting for gas efficiency. No external imports.
 */
contract NFTMint {
    // -------------------- ERC721 core storage --------------------
    string public name = "MyNFT";
    string public symbol = "MNFT";

    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 5555;
    uint256 public constant MAX_PER_WALLET = 3;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    string private _baseTokenURI;

    // -------------------- Mint config --------------------
    uint256 public constant ALLOWLIST_PRICE = 0.05 ether;
    uint256 public constant PUBLIC_PRICE = 0.08 ether;

    bytes32 public merkleRoot;
    bool public allowlistActive;
    bool public publicActive;

    address public owner;

    // Track mints per wallet (both phases combined)
    mapping(address => uint256) public mintedPerWallet;
    // Prevent allowlist address reuse
    mapping(address => bool) public allowlistClaimed;

    // -------------------- Events --------------------
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    event AllowlistMint(address indexed to, uint256 quantity);
    event PublicMint(address indexed to, uint256 quantity);
    event Withdraw(address indexed to, uint256 amount);

    // -------------------- Modifiers --------------------
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonReentrant() {
        require(_status != 2, "Reentrant");
        _status = 2;
        _;
        _status = 1;
    }
    uint256 private _status = 1;

    // -------------------- Constructor --------------------
    constructor(bytes32 _merkleRoot, string memory baseURI) {
        owner = msg.sender;
        merkleRoot = _merkleRoot;
        _baseTokenURI = baseURI;
    }

    // -------------------- Admin --------------------
    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        merkleRoot = _merkleRoot;
    }

    function setBaseURI(string calldata baseURI) external onlyOwner {
        _baseTokenURI = baseURI;
    }

    function setAllowlistActive(bool active) external onlyOwner {
        allowlistActive = active;
    }

    function setPublicActive(bool active) external onlyOwner {
        publicActive = active;
    }

    function withdraw(address to) external onlyOwner nonReentrant {
        require(to != address(0), "Zero address");
        uint256 balance = address(this).balance;
        (bool ok, ) = payable(to).call{value: balance}("");
        require(ok, "Withdraw failed");
        emit Withdraw(to, balance);
    }

    // -------------------- Mint: Allowlist --------------------
    function allowlistMint(uint256 quantity, bytes32[] calldata proof) external payable {
        require(allowlistActive, "Allowlist not active");
        require(quantity > 0, "Quantity 0");
        require(!allowlistClaimed[msg.sender], "Already claimed");
        require(
            mintedPerWallet[msg.sender] + quantity <= MAX_PER_WALLET,
            "Exceeds max per wallet"
        );
        require(totalSupply + quantity <= MAX_SUPPLY, "Sold out");
        require(msg.value == ALLOWLIST_PRICE * quantity, "Wrong ETH");

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(_verify(proof, merkleRoot, leaf), "Invalid proof");

        allowlistClaimed[msg.sender] = true;
        mintedPerWallet[msg.sender] += quantity;
        _mint(msg.sender, quantity);

        emit AllowlistMint(msg.sender, quantity);
    }

    // -------------------- Mint: Public --------------------
    function publicMint(uint256 quantity) external payable {
        require(publicActive, "Public not active");
        require(quantity > 0, "Quantity 0");
        require(
            mintedPerWallet[msg.sender] + quantity <= MAX_PER_WALLET,
            "Exceeds max per wallet"
        );
        require(totalSupply + quantity <= MAX_SUPPLY, "Sold out");
        require(msg.value == PUBLIC_PRICE * quantity, "Wrong ETH");

        mintedPerWallet[msg.sender] += quantity;
        _mint(msg.sender, quantity);

        emit PublicMint(msg.sender, quantity);
    }

    // -------------------- Merkle verify --------------------
    function _verify(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (computed <= p) {
                computed = keccak256(abi.encodePacked(computed, p));
            } else {
                computed = keccak256(abi.encodePacked(p, computed));
            }
        }
        return computed == root;
    }

    // -------------------- ERC721 implementation --------------------
    function balanceOf(address account) public view returns (uint256) {
        require(account != address(0), "Zero address");
        return _balances[account];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address o = _owners[tokenId];
        require(o != address(0), "Nonexistent token");
        return o;
    }

    function approve(address to, uint256 tokenId) public {
        address tokenOwner = ownerOf(tokenId);
        require(msg.sender == tokenOwner || isApprovedForAll(tokenOwner, msg.sender), "Not authorized");
        _tokenApprovals[tokenId] = to;
        emit Approval(tokenOwner, to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "Nonexistent token");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != msg.sender, "Self approval");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address tokenOwner, address operator) public view returns (bool) {
        return _operatorApprovals[tokenOwner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not authorized");
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not authorized");
        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    function tokenURI(uint256 tokenId) public view returns (string memory) {
        require(_owners[tokenId] != address(0), "Nonexistent token");
        return string(abi.encodePacked(_baseTokenURI, _toString(tokenId)));
    }

    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165
            interfaceId == 0x80ac58cd || // ERC721
            interfaceId == 0x5b5e139f;   // ERC721Metadata
    }

    // -------------------- Internal ERC721 --------------------
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address tokenOwner = ownerOf(tokenId);
        return (
            spender == tokenOwner ||
            getApproved(tokenId) == spender ||
            isApprovedForAll(tokenOwner, spender)
        );
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        require(ownerOf(tokenId) == from, "Wrong owner");
        require(to != address(0), "Zero address");

        delete _tokenApprovals[tokenId];
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function _mint(address to, uint256 quantity) internal {
        require(to != address(0), "Zero address");
        uint256 startId = totalSupply;
        for (uint256 i = 0; i < quantity; i++) {
            uint256 tokenId = startId + i;
            _owners[tokenId] = to;
            emit Transfer(address(0), to, tokenId);
        }
        _balances[to] += quantity;
        totalSupply += quantity;
    }

    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) internal {
        if (to.code.length > 0) {
            bytes4 retval = IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data);
            require(retval == IERC721Receiver.onERC721Received.selector, "Unsafe recipient");
        }
    }

    // -------------------- Utils --------------------
    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
