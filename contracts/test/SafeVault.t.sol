// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SafeVault} from "../src/SafeVault.sol";

contract SafeVaultTest is Test {
    SafeVault internal vault;
    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        vault = new SafeVault(owner);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ------------------------------------------------------------------ constructor

    function test_Constructor_SetsOwner() public view {
        assertEq(vault.owner(), owner);
        assertEq(vault.pendingOwner(), address(0));
        assertFalse(vault.paused());
        assertEq(vault.VERSION(), "1.0.0");
    }

    function test_Constructor_RevertsOnZeroOwner() public {
        vm.expectRevert(SafeVault.ZeroAddress.selector);
        new SafeVault(address(0));
    }

    // ------------------------------------------------------------------ deposits

    function test_Deposit_CreditsSender() public {
        vm.expectEmit(true, false, false, true, address(vault));
        emit SafeVault.Deposited(alice, 1 ether);

        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        assertEq(vault.balanceOf(alice), 1 ether);
        assertEq(vault.totalDeposits(), 1 ether);
        assertEq(address(vault).balance, 1 ether);
    }

    function test_Receive_IsADeposit() public {
        vm.prank(alice);
        (bool ok,) = address(vault).call{value: 2 ether}("");
        assertTrue(ok);
        assertEq(vault.balanceOf(alice), 2 ether);
    }

    function test_Deposit_RevertsOnZero() public {
        vm.prank(alice);
        vm.expectRevert(SafeVault.ZeroAmount.selector);
        vault.deposit{value: 0}();
    }

    function test_Deposit_RevertsWhenPaused() public {
        vm.prank(owner);
        vault.pause();

        vm.prank(alice);
        vm.expectRevert(SafeVault.DepositsPaused.selector);
        vault.deposit{value: 1 ether}();
    }

    // ------------------------------------------------------------------ withdrawals

    function test_Withdraw_ReturnsFunds() public {
        vm.startPrank(alice);
        vault.deposit{value: 3 ether}();
        vault.withdraw(1 ether);
        vm.stopPrank();

        assertEq(vault.balanceOf(alice), 2 ether);
        assertEq(vault.totalDeposits(), 2 ether);
        assertEq(alice.balance, 98 ether);
    }

    function test_Withdraw_StillWorksWhenPaused() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();
        vm.prank(owner);
        vault.pause();

        vm.prank(alice);
        vault.withdraw(1 ether);
        assertEq(alice.balance, 100 ether);
    }

    function test_Withdraw_RevertsOnInsufficientBalance() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(SafeVault.InsufficientBalance.selector, 2 ether, 1 ether)
        );
        vault.withdraw(2 ether);
    }

    function test_Withdraw_CannotTakeSomeoneElsesFunds() public {
        vm.prank(alice);
        vault.deposit{value: 5 ether}();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.InsufficientBalance.selector, 1, 0));
        vault.withdraw(1);
    }

    function test_Withdraw_RevertsOnZero() public {
        vm.prank(alice);
        vm.expectRevert(SafeVault.ZeroAmount.selector);
        vault.withdraw(0);
    }

    function test_Withdraw_ReentrancyIsBlocked() public {
        Reenterer attacker = new Reenterer(vault);
        vm.deal(address(attacker), 1 ether);
        attacker.depositToVault(1 ether);

        // Victim funds that the attacker would like to drain.
        vm.prank(alice);
        vault.deposit{value: 10 ether}();

        // The nested withdraw reverts with Reentrancy, so the outer call fails with TransferFailed.
        vm.expectRevert(SafeVault.TransferFailed.selector);
        attacker.attack(1 ether);

        assertEq(address(vault).balance, 11 ether);
        assertEq(vault.balanceOf(address(attacker)), 1 ether);
    }

    // ------------------------------------------------------------------ admin

    function test_Pause_OnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, alice));
        vault.pause();

        vm.prank(owner);
        vault.pause();
        assertTrue(vault.paused());

        vm.prank(owner);
        vault.unpause();
        assertFalse(vault.paused());
    }

    function test_Unpause_OnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, alice));
        vault.unpause();
    }

    function test_Ownership_TwoStepTransfer() public {
        vm.prank(owner);
        vault.transferOwnership(bob);
        assertEq(vault.owner(), owner, "owner must not change until accepted");
        assertEq(vault.pendingOwner(), bob);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, alice));
        vault.acceptOwnership();

        vm.prank(bob);
        vault.acceptOwnership();
        assertEq(vault.owner(), bob);
        assertEq(vault.pendingOwner(), address(0));
    }

    function test_Ownership_TransferCanBeCancelled() public {
        vm.startPrank(owner);
        vault.transferOwnership(bob);
        vault.cancelOwnershipTransfer();
        vm.stopPrank();
        assertEq(vault.pendingOwner(), address(0));

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, bob));
        vault.acceptOwnership();
    }

    function test_Ownership_RejectsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(SafeVault.ZeroAddress.selector);
        vault.transferOwnership(address(0));
    }

    function test_Ownership_OnlyOwnerCanCancel() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, alice));
        vault.cancelOwnershipTransfer();
    }

    function test_Ownership_OnlyOwnerCanStart() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, alice));
        vault.transferOwnership(alice);
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_DepositWithdraw_RoundTrip(uint96 depositAmount, uint96 withdrawAmount)
        public
    {
        depositAmount = uint96(bound(depositAmount, 1, 100 ether));
        withdrawAmount = uint96(bound(withdrawAmount, 1, depositAmount));

        vm.startPrank(alice);
        vault.deposit{value: depositAmount}();
        vault.withdraw(withdrawAmount);
        vm.stopPrank();

        assertEq(vault.balanceOf(alice), uint256(depositAmount) - withdrawAmount);
        assertEq(vault.totalDeposits(), uint256(depositAmount) - withdrawAmount);
        assertEq(alice.balance, 100 ether - uint256(depositAmount) + withdrawAmount);
    }

    function testFuzz_Withdraw_NeverExceedsBalance(uint96 depositAmount, uint256 withdrawAmount)
        public
    {
        depositAmount = uint96(bound(depositAmount, 1, 100 ether));
        withdrawAmount = bound(withdrawAmount, uint256(depositAmount) + 1, type(uint256).max);

        vm.prank(alice);
        vault.deposit{value: depositAmount}();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                SafeVault.InsufficientBalance.selector, withdrawAmount, depositAmount
            )
        );
        vault.withdraw(withdrawAmount);
    }

    function testFuzz_OnlyOwnerCanPause(address caller) public {
        vm.assume(caller != owner);
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(SafeVault.Unauthorized.selector, caller));
        vault.pause();
    }
}

/// @dev Malicious depositor that re-enters `withdraw` from its receive hook.
contract Reenterer {
    SafeVault internal immutable vault;

    constructor(SafeVault vault_) {
        vault = vault_;
    }

    function depositToVault(uint256 amount) external {
        vault.deposit{value: amount}();
    }

    function attack(uint256 amount) external {
        vault.withdraw(amount);
    }

    receive() external payable {
        vault.withdraw(msg.value);
    }
}
