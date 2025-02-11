// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract ExternalSigner is UUPSUpgradeable, Initializable, IERC1271 {
    mapping(bytes32 => bool) public usedHash;
    mapping(bytes32 => mapping(address => bool)) public confirmation;

    uint256 public ownerCount;
    mapping(uint256 => address) public owners;
    mapping(address => bool) public isOwner;

    uint256 public required;

    event AddOwner(address owner);
    event RemoveOwner(address owner);
    event ChangeRequirement(uint256 required);

    modifier onlySelf() {
        _onlySelf();
        _;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    constructor() { _disableInitializers(); }
    receive() external payable {}

    function version() external pure returns (string memory) {
        return "ExternalSigner240621";
    }

    function _onlySelf() internal view {
        //through the account itself (which gets redirected through execute())
        require(msg.sender == address(this), "only self");
    }

    function _onlyOwner() internal view {
        require(isOwner[msg.sender], "only owner");
    }

    function initialize(address[] calldata owners_, uint256 required_) public virtual initializer {
        _initialize(owners_, required_);
    }

    function _initialize(address[] calldata owners_, uint256 required_) internal virtual {
        for(uint256 i = 0; i < owners_.length; i++) _addOwner(owners_[i]);
        _changeRequirement(required_);
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        bytes32 signingHash = MessageHashUtils.toEthSignedMessageHash(hash);

        address owner = ECDSA.recover(signingHash, signature);
        if(isOwner[owner]) return IERC1271.isValidSignature.selector;

        return 0xffffffff;
    }

    function execute(address dest, uint256 value, bytes calldata func, uint256 validUntil, bytes[] calldata signatures) external onlyOwner {
        require(block.timestamp <= validUntil);
        _validateSignature(dest, value, func, validUntil, signatures);
        _call(dest, value, func);
    }

    function _validateSignature(address dest, uint256 value, bytes calldata func, uint256 validUntil, bytes[] calldata signatures) internal {
        require(signatures.length >= required);

        bytes32 hash = keccak256(abi.encode(address(this), getChainId(), dest, value, func, validUntil));
        bytes32 signingHash = MessageHashUtils.toEthSignedMessageHash(hash);
        require(!usedHash[signingHash]);

        uint256 validatedCount = 0;
        for(uint256 i = 0; i < signatures.length; i++){
            address owner = ECDSA.recover(signingHash, signatures[i]);
            require(isOwner[owner]);

            require(!confirmation[signingHash][owner]);
            confirmation[signingHash][owner] = true;
            validatedCount += 1;
        }
        require(validatedCount >= required);
        usedHash[signingHash] = true;
    }

    function addOwner(address owner) public onlySelf {
        _addOwner(owner);
    }

    function _addOwner(address owner) internal {
        require(owner != address(0));
        require(!isOwner[owner]);

        owners[ownerCount] = owner;
        ownerCount += 1;
        isOwner[owner] = true;

        emit AddOwner(owner);
    }

    function removeOwner(address owner) public onlySelf {
        _removeOwner(owner);
    }

    function _removeOwner(address owner) internal {
        require(owner != address(0));
        require(isOwner[owner]);

        uint256 i = 0;
        for(i = 0; i < ownerCount; i++){
            if(owner == owners[i]) break;
        }

        uint256 newOwnerCount = ownerCount - 1;
        require(newOwnerCount >= required);

        isOwner[owner] = false;
        owners[i] = owners[newOwnerCount];
        owners[newOwnerCount] = address(0);
        ownerCount = newOwnerCount;

        emit RemoveOwner(owner);
    }

    function changeRequirement(uint256 required_) public onlySelf {
        _changeRequirement(required_);
    }

    function _changeRequirement(uint256 required_) internal {
        require(required_ != 0);
        require(ownerCount >= required_);

        required = required_;
        emit ChangeRequirement(required);
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlySelf();
    }

    function getChainId() public view returns (uint256 chainId) {
        assembly {
            chainId := chainid()
        }
    }
}
