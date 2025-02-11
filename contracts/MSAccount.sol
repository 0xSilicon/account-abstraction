// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {BaseAccount} from "../../core/BaseAccount.sol";
import {TokenCallbackHandler} from "../../samples/callback/TokenCallbackHandler.sol";
import {PackedUserOperation} from "../../interfaces/IEntryPoint.sol";
import {IEntryPoint} from "../../interfaces/IEntryPoint.sol";
import {_packValidationData, SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "../../core/Helpers.sol";

contract MSAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    address public owner;
    IERC1271 private  _externalSigner;

    address public recoverOwner;
    uint256 public recoverCount;

    IEntryPoint private immutable _entryPoint;

    event MSAccountInitialized(IEntryPoint indexed entryPoint, address indexed externalSigner, address indexed owner);
    event OwnershipRecovered(address indexed previousOwner, address indexed newOwner, uint256 recoverNonce);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event SetRecoverOwner(address indexed previousRecoverOwner, address indexed newRecoverOwner);
    event SetExternalSigner(address indexed previousExternalSigner, address indexed newExternalSigner);

    modifier onlySelf() {
        _onlySelf();
        _;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    function externalSigner() public view returns (IERC1271) {
        return _externalSigner;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function version() external pure returns (string memory) {
        return "MSAccount240827";
    }

    function _onlySelf() internal view {
        //through the account itself (which gets redirected through execute())
        require(msg.sender == address(this), "only self");
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     * @param dest destination address to call
     * @param value the value to pass in this call
     * @param func the calldata to pass in this call
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPoint();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     * @dev to reduce gas consumption for trivial case (no value), use a zero-length array to mean zero value
     * @param dest an array of destination addresses
     * @param value an array of values to pass to each call. can be zero-length for no-value calls
     * @param func an array of calldata to pass to each call
     */
    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func) external {
        _requireFromEntryPoint();
        require(dest.length == func.length && (value.length == 0 || value.length == func.length), "wrong array lengths");
        if (value.length == 0) {
            for (uint256 i = 0; i < dest.length; i++) {
                _call(dest[i], 0, func[i]);
            }
        } else {
            for (uint256 i = 0; i < dest.length; i++) {
                _call(dest[i], value[i], func[i]);
            }
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
      * @param anOwner the owner (signer) of this account
     */
    function initialize(address anOwner, address anExternalSigner) public virtual initializer {
        _initialize(anOwner, anExternalSigner);
    }

    function _initialize(address anOwner, address anExternalSigner) internal virtual {
        owner = anOwner;
        _externalSigner = IERC1271(anExternalSigner);

        emit OwnershipTransferred(address(0), anOwner);
        if(anExternalSigner != address(0)) emit SetExternalSigner(address(0), anExternalSigner);

        emit MSAccountInitialized(_entryPoint, anExternalSigner, owner);
    }

    function getUserOperationHash(uint48 validUntil, uint48 validAfter, bytes32 userOpHash) public pure returns (bytes32){
        return keccak256(
            abi.encode(
                "MSAccount:UserOperation",
                validUntil,
                validAfter,
                userOpHash
            )
        );
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        bytes32 signingHash = MessageHashUtils.toEthSignedMessageHash(hash);
        if(address(externalSigner()) == address(0)) {
            if (owner == ECDSA.recover(signingHash, signature)) {
                return IERC1271.isValidSignature.selector;
            }

            return 0xffffffff;
        }

        if(signature.length <= 65) return 0xffffffff;

        bytes memory signatureOwner = signature[:65];
        if(ECDSA.recover(signingHash, signatureOwner) != owner) return 0xffffffff;

        bytes memory signatureExternalSigner = signature[65:];
        if(externalSigner().isValidSignature(hash, signatureExternalSigner) != IERC1271.isValidSignature.selector) return 0xffffffff;

        return IERC1271.isValidSignature.selector;
    }

    /// implement template method of BaseAccount
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        if(address(externalSigner()) == address(0)) return _validateSingleSignature(userOp, userOpHash);

        if(userOp.signature.length <= 65) return SIG_VALIDATION_FAILED;

        (uint48 validUntil, uint48 validAfter, bytes memory signatureOwner, bytes memory signatureExternalSigner) = abi.decode(userOp.signature, (uint48, uint48, bytes, bytes));

        bytes32 dataHash = getUserOperationHash(validUntil, validAfter, userOpHash);
        bytes32 signingHash = MessageHashUtils.toEthSignedMessageHash(dataHash);
        if(owner != ECDSA.recover(signingHash, signatureOwner)) return SIG_VALIDATION_FAILED;
        if(externalSigner().isValidSignature(dataHash, signatureExternalSigner) != IERC1271.isValidSignature.selector) return SIG_VALIDATION_FAILED;

        return _packValidationData(false, validUntil, validAfter);
    }

    function _validateSingleSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal virtual returns (uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, bytes memory signature) = abi.decode(userOp.signature, (uint48, uint48, bytes));

        bytes32 dataHash = getUserOperationHash(validUntil, validAfter, userOpHash);
        bytes32 signingHash = MessageHashUtils.toEthSignedMessageHash(dataHash);
        if (owner != ECDSA.recover(signingHash, signature)) return SIG_VALIDATION_FAILED;

        return _packValidationData(false, validUntil, validAfter);
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlySelf {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function getOwnershipHash(uint256 recoverNonce, address currentOwner, address newOwner, uint48 validUntil) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "MSAccount:Ownership",
                address(this),
                block.chainid,
                recoverNonce,
                currentOwner,
                newOwner,
                validUntil
            )
        );
    }

    function transferOwnershipBySignature(address newOwner, uint48 validUntil, bytes calldata signature) public {
        require(validUntil >= block.timestamp);

        uint256 nonce = recoverCount;
        emit OwnershipRecovered(owner, newOwner, nonce);

        bytes32 dataHash = getOwnershipHash(nonce, owner, newOwner, validUntil);

        bytes memory signatureRecoverOwner = signature[:65];
        bytes32 signingHash = MessageHashUtils.toEthSignedMessageHash(dataHash);
        require(recoverOwner == ECDSA.recover(signingHash, signatureRecoverOwner));

        if(address(externalSigner()) != address(0)){
            bytes memory signatureExternalSigner = signature[65:];
            bytes4 externalSignerMagicValue = externalSigner().isValidSignature(dataHash, signatureExternalSigner);
            require(externalSignerMagicValue == IERC1271.isValidSignature.selector);
        }
        recoverCount = recoverCount + 1;

        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setRecoverOwner(address newRecoverOwner) public onlySelf {
        _setRecoverOwner(newRecoverOwner);
    }

    function _setRecoverOwner(address newRecoverOwner) internal {
        require(owner != newRecoverOwner);
        emit SetRecoverOwner(recoverOwner, newRecoverOwner);
        recoverOwner = newRecoverOwner;
    }

    function setExternalSigner(address newExternalSigner) public onlySelf {
        _setExternalSigner(newExternalSigner);
    }

    function _setExternalSigner(address newExternalSigner) internal {
        emit SetExternalSigner(address(externalSigner()), newExternalSigner);
        _externalSigner = IERC1271(newExternalSigner);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlySelf();
    }
}

