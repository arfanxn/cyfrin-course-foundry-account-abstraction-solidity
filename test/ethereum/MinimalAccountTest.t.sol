// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {MinimalAccount, SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "src/ethereum/MinimalAccount.sol";
import {DeployMinimalAccount} from "script/DeployMinimalAccount.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SendPackedUserOp} from "script/SendPackedUserOp.s.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MinimalAccountTest is Test {
    using MessageHashUtils for bytes32;

    HelperConfig helperConfig;
    MinimalAccount minimalAccount;
    ERC20Mock usdc;
    SendPackedUserOp sendPackedUserOp;

    uint256 private constant AMOUNT = 1e18;

    function setUp() public {
        DeployMinimalAccount deployer = new DeployMinimalAccount();
        (helperConfig, minimalAccount) = deployer.deploy();
        usdc = new ERC20Mock();
        sendPackedUserOp = new SendPackedUserOp();
    }

    /**
     * @notice test that owner can execute commands on the minimal account
     */
    function testOwnerCanExecuteCommands() public {
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, funcData);

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testNonOwnerCannotExecuteCommands() public {
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        address randomUser = makeAddr("randomUser");
        vm.prank(randomUser);
        vm.expectRevert(
            MinimalAccount.MinimalAccount__NotFromEntryPointOrOwner.selector
        );
        minimalAccount.execute(dest, value, funcData);
    }

    function testRecoverSignedOp() public {
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory executeCallData = abi.encodeWithSelector(
            MinimalAccount.execute.selector,
            dest,
            value,
            funcData
        );
        PackedUserOperation memory packedUserOp = sendPackedUserOp
            .generateSignedUserOperation(
                executeCallData,
                helperConfig.getConfig(),
                address(minimalAccount)
            );
        bytes32 userOperationHash = IEntryPoint(
            helperConfig.getConfig().entryPoint
        ).getUserOpHash(packedUserOp);

        address actualSigner = ECDSA.recover(
            userOperationHash.toEthSignedMessageHash(),
            packedUserOp.signature
        );

        address expectedSigner = minimalAccount.owner();
        assertEq(actualSigner, expectedSigner);
    }

    function testValidationOfUserOps() public {
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory executeCallData = abi.encodeWithSelector(
            MinimalAccount.execute.selector,
            dest,
            value,
            funcData
        );
        PackedUserOperation memory packedUserOp = sendPackedUserOp
            .generateSignedUserOperation(
                executeCallData,
                helperConfig.getConfig(),
                address(minimalAccount)
            );
        bytes32 userOperationHash = IEntryPoint(
            helperConfig.getConfig().entryPoint
        ).getUserOpHash(packedUserOp);
        uint256 missingAccountFunds = 1e18;

        vm.prank(helperConfig.getConfig().entryPoint);
        uint256 validationData = minimalAccount.validateUserOp(
            packedUserOp,
            userOperationHash,
            missingAccountFunds
        );
        assertEq(validationData, SIG_VALIDATION_SUCCESS);
    }

    function testEntryPointCanExecuteCommands() public {
        assertEq(usdc.balanceOf(address(minimalAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );
        bytes memory executeCallData = abi.encodeWithSelector(
            MinimalAccount.execute.selector,
            dest,
            value,
            funcData
        );
        PackedUserOperation memory packedUserOp = sendPackedUserOp
            .generateSignedUserOperation(
                executeCallData,
                helperConfig.getConfig(),
                address(minimalAccount)
            );
        // bytes32 userOperationHash = IEntryPoint(helperConfig.getConfig().entryPoint).getUserOpHash(packedUserOp);
        vm.deal(address(minimalAccount), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = packedUserOp;

        address randomUser = makeAddr("randomUser");
        vm.prank(randomUser);
        IEntryPoint(helperConfig.getConfig().entryPoint).handleOps(
            ops,
            payable(randomUser)
        );

        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }
}
