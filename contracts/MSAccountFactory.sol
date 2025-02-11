// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./MSAccount.sol";

contract MSAccountFactory {
    MSAccount public immutable accountImplementation;

    constructor(IEntryPoint _entryPoint) {
        accountImplementation = new MSAccount(_entryPoint);
    }

    function version() external pure returns (string memory) {
        return "MSAccountFactory240523";
    }

    function createAccount(address owner, address externalSigner, uint256 salt) public returns (MSAccount ret) {
        address addr = getAddress(owner, externalSigner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return MSAccount(payable(addr));
        }
        ret = MSAccount(payable(new ERC1967Proxy{salt : bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(MSAccount.initialize, (owner, externalSigner))
            )));
    }

    function getAddress(address owner, address externalSigner, uint256 salt) public view returns (address) {
        return Create2.computeAddress(bytes32(salt), keccak256(abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(
                    address(accountImplementation),
                    abi.encodeCall(MSAccount.initialize, (owner, externalSigner))
                )
            )));
    }
}
