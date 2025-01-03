// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Utils} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {NONCE_HOLDER_SYSTEM_CONTRACT, BOOTLOADER_FORMAL_ADDRESS, DEPLOYER_SYSTEM_CONTRACT} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {SystemContractsCaller} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {Transaction, MemoryTransactionHelper} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * Lifecycle of a type 113 (0x71) transaction
 * msg.sender is the bootloader system contract
 *
 * Phase 1 Validation
 * 1. The user sends the transaction to the "zkSync API client" (sort of a "light node")
 * 2. The zkSync API client checks to see the the nonce is unique by querying the NonceHolder system contract
 * 3. The zkSync API client calls validateTransaction, which MUST update the nonce
 * 4. The zkSync API client checks the nonce is updated
 * 5. The zkSync API client calls payForTransaction, or prepareForPaymaster & validateAndPayForPaymasterTransaction
 * 6. The zkSync API client verifies that the bootloader gets paid
 *
 * Phase 2 Execution
 * 7. The zkSync API client passes the validated transaction to the main node / sequencer (as of today, they are the same)
 * 8. The main node calls executeTransaction
 * 9. If a paymaster was used, the postTransaction is called
 */
contract ZkMinimalAccount is IAccount, Ownable {
    error ZkMinimalAccount__InsufficientBalance();
    error ZkMinimalAccount__NotFromBootloader();
    error ZkMinimalAccount__NotFromBootloaderOrOwner();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__FailedToPay();
    error ZkMinimalAccount__InvalidSignature();

    using MemoryTransactionHelper for Transaction;

    modifier requiredFromBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS)
            revert ZkMinimalAccount__NotFromBootloader();
        _;
    }
    modifier requiredFromBootloaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner())
            revert ZkMinimalAccount__NotFromBootloader();
        _;
    }

    constructor() Ownable(msg.sender) {
        //
    }

    receive() external payable {
        //
    }

    function validateTransaction(
        bytes32 /*_txHash*/,
        bytes32 /*_suggestedSignedHash*/,
        Transaction memory _transaction
    ) external payable requiredFromBootloader returns (bytes4 magic) {
        magic = _validateTransaction(_transaction);
    }

    function executeTransaction(
        bytes32 /*_txHash*/,
        bytes32 /*_suggestedSignedHash*/,
        Transaction memory _transaction
    ) external payable requiredFromBootloaderOrOwner {
        _executeTransaction(_transaction);
    }

    function executeTransactionFromOutside(
        Transaction memory _transaction
    ) external payable {
        bytes4 magic = _validateTransaction(_transaction);
        if (magic != ACCOUNT_VALIDATION_SUCCESS_MAGIC)
            revert ZkMinimalAccount__InvalidSignature();
        _executeTransaction(_transaction);
    }

    function payForTransaction(
        bytes32 /* _txHash */,
        bytes32 /* _suggestedSignedHash */,
        Transaction memory _transaction
    ) external payable {
        bool success = _transaction.payToTheBootloader();
        if (!success) revert ZkMinimalAccount__FailedToPay();
    }

    function prepareForPaymaster(
        bytes32 _txHash,
        bytes32 _possibleSignedHash,
        Transaction memory _transaction
    ) external payable {
        // * KEPT BLANK
    }

    function _validateTransaction(
        Transaction memory _transaction
    ) internal returns (bytes4 magic) {
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(
                INonceHolder.incrementMinNonceIfEquals,
                (_transaction.nonce)
            )
        );

        // Check for fee to pay
        uint256 totalRequireBalance = _transaction.totalRequiredBalance();
        if (totalRequireBalance > address(this).balance) {
            revert ZkMinimalAccount__InsufficientBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash();
        // bytes32 convertedHash = MessageHashUtils.toEthSignedMessageHash(txHash);
        address signer = ECDSA.recover(txHash, _transaction.signature);
        magic = signer == owner()
            ? ACCOUNT_VALIDATION_SUCCESS_MAGIC
            : bytes4(0);
        return magic;
    }

    function _executeTransaction(
        Transaction memory _transaction
    ) internal requiredFromBootloaderOrOwner {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(
                gas,
                to,
                value,
                data
            );
        } else {
            bool success;
            assembly {
                success := call(
                    gas(),
                    to,
                    value,
                    add(data, 0x20),
                    mload(data),
                    0,
                    0
                )
            }
            if (!success) revert ZkMinimalAccount__ExecutionFailed();
        }
    }
}
