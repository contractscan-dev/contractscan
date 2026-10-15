// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MyNFTCollection
 * @notice ERC721 with whitelist presale, public sale, reveal, and withdraw.
 *         Self-contained — no imports.
 */
contract MyNFTCollection {
    // ---------------------------------------------------------------------
    //                                ERC721
    // ---------------------------------------------------------------------
    string public name = "My NFT Collection";
    string public symbol = "MNFT";

    uint256 public totalSupply;
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "ERC721: zero address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: nonexistent token");
        return owner;
    }

    function approve(address to, uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(to != owner, "ERC721: self approval");
        require(msg.sender == owner || _operatorApprovals[owner][msg.sender], "ERC721: not authorized");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "ERC721: nonexistent token");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != msg.sender, "ERC721: self approval");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "ERC721: not authorized");
        require(ownerOf(tokenId) == from, "ERC721: wrong from");
        require(to != address(0), "ERC721: zero address");

        delete _tokenApprovals[tokenId];
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId), "ERC721: unsafe recipient");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) public {
        transferFrom(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, data), "ERC721: unsafe recipient");
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = ownerOf(tokenId);
        return (spender == owner || _operatorApprovals[owner][spender] || _tokenApprovals[tokenId] == spender);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId) internal returns (bool) {
        return _checkOnERC721Received(from, to, tokenId, "");
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) internal returns (bool) {
        if (to.code.length == 0) return true;
        (bool success, bytes memory ret) = to.call(
            abi.encodeWithSignature("onERC721Received(address,address,uint256,bytes)", msg.sender, from, tokenId, data)
        );
        if (!success) return false;
        if (ret.length < 32) return false;
        bytes4 selector = abi.decode(ret, (bytes4));
        return selector == 0x150b7a02; // IERC721Receiver.onERC721Received.selector
    }

    // ---------------------------------------------------------------------
    //                              METADATA
    // ---------------------------------------------------------------------
    string private _baseTokenURI;
    bool public revealed;

    /// @notice Placeholder URI shown before reveal (e.g. IPFS "unrevealed" JSON)
    string public notRevealedURI = "ipfs://REPLACE_WITH_PREREVEAL_CID/";

    function tokenURI(uint256 tokenId) public view returns (string memory) {
        require(_owners[tokenId] != address(0), "ERC721: nonexistent token");
        if (!revealed) return notRevealedURI;
        return string(abi.encodePacked(_baseTokenURI, _toString(tokenId), ".json"));
    }

    function _toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    // ---------------------------------------------------------------------
    //                              SALE CONFIG
    // ---------------------------------------------------------------------
    address public owner;
    uint256 public maxSupply = 10000;
    uint256 public maxPerWallet = 5;

    uint256 public presalePrice = 0.03 ether;
    uint256 public publicPrice  = 0.05 ether;

    bool public presaleActive;
    bool public publicSaleActive;

    mapping(address => bool) public whitelist;
    mapping(address => uint256) public mintedPerWallet;

    event Minted(address indexed to, uint256 indexed tokenId);
    event Revealed(string baseURI);
    event Withdrawn(address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ---------------------------------------------------------------------
    //                          OWNER: WHITELIST
    // ---------------------------------------------------------------------
    function addToWhitelist(address[] calldata accounts) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            whitelist[accounts[i]] = true;
        }
    }

    function removeFromWhitelist(address[] calldata accounts) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            whitelist[accounts[i]] = false;
        }
    }

    // ---------------------------------------------------------------------
    //                          OWNER: SALE TOGGLES
    // ---------------------------------------------------------------------
    function setPresaleActive(bool active) external onlyOwner { presaleActive = active; }
    function setPublicSaleActive(bool active) external onlyOwner { publicSaleActive = active; }
    function setPresalePrice(uint256 price) external onlyOwner { presalePrice = price; }
    function setPublicPrice(uint256 price) external onlyOwner { publicPrice = price; }
    function setMaxPerWallet(uint256 max) external onlyOwner { maxPerWallet = max; }
    function setMaxSupply(uint256 max) external onlyOwner { maxSupply = max; }
    function setNotRevealedURI(string calldata uri) external onlyOwner { notRevealedURI = uri; }

    // ---------------------------------------------------------------------
    //                              MINT
    // ---------------------------------------------------------------------
    function presaleMint(uint256 quantity) external payable {
        require(presaleActive, "Presale not active");
        require(whitelist[msg.sender], "Not whitelisted");
        _mintInternal(msg.sender, quantity, presalePrice);
    }

    function publicMint(uint256 quantity) external payable {
        require(publicSaleActive, "Public sale not active");
        _mintInternal(msg.sender, quantity, publicPrice);
    }

    function _mintInternal(address to, uint256 quantity, uint256 price) internal {
        require(quantity > 0, "Quantity 0");
        require(totalSupply + quantity <= maxSupply, "Exceeds max supply");
        require(mintedPerWallet[to] + quantity <= maxPerWallet, "Exceeds wallet limit");
        require(msg.value == price * quantity, "Wrong ETH amount");

        mintedPerWallet[to] += quantity;
        for (uint256 i = 0; i < quantity; i++) {
            uint256 tokenId = totalSupply + 1;
            totalSupply = tokenId;
            _owners[tokenId] = to;
            _balances[to] += 1;
            emit Transfer(address(0), to, tokenId);
            emit Minted(to, tokenId);
        }
    }

    // ---------------------------------------------------------------------
    //                              REVEAL
    // ---------------------------------------------------------------------
    /// @notice Set the real base URI and flip revealed to true. One-shot.
    function reveal(string calldata baseURI_) external onlyOwner {
        require(!revealed, "Already revealed");
        require(bytes(baseURI_).length > 0, "Empty URI");
        _baseTokenURI = baseURI_;
        revealed = true;
        emit Revealed(baseURI_);
    }

    // ---------------------------------------------------------------------
    //                              WITHDRAW
    // ---------------------------------------------------------------------
    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "Nothing to withdraw");
        (bool ok, ) = payable(owner).call{value: balance}("");
        require(ok, "Withdraw failed");
        emit Withdrawn(owner, balance);
    }

    // ---------------------------------------------------------------------
    //                              MISC
    // ---------------------------------------------------------------------
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    /// @notice ERC165: declares support for ERC721 + ERC721Metadata
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC165
            interfaceId == 0x80ac58cd || // ERC721
            interfaceId == 0x5b5e139f;   // ERC721Metadata
    }
}
