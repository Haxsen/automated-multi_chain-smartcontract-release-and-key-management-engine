// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SafeVault} from "../src/SafeVault.sol";

/// @dev Drives SafeVault with bounded, always-valid actions so `fail_on_revert = true`
///      surfaces any unexpected revert as a bug. Ghost variables track what *should* be true.
contract VaultHandler is Test {
    SafeVault public immutable vault;
    address public immutable owner;

    address[] internal actors;
    uint256 public ghostDeposited;
    uint256 public ghostWithdrawn;
    uint256 public ghostForcedEth;

    constructor(SafeVault vault_, address owner_) {
        vault = vault_;
        owner = owner_;
        for (uint256 i = 0; i < 5; i++) {
            actors.push(makeAddr(string.concat("actor", vm.toString(i))));
        }
    }

    function deposit(uint256 actorSeed, uint256 amount) external {
        if (vault.paused()) return;
        address actor = _actor(actorSeed);
        amount = bound(amount, 1, 1_000 ether);
        vm.deal(actor, actor.balance + amount);

        vm.prank(actor);
        vault.deposit{value: amount}();
        ghostDeposited += amount;
    }

    function withdraw(uint256 actorSeed, uint256 amount) external {
        address actor = _actor(actorSeed);
        uint256 balance = vault.balanceOf(actor);
        if (balance == 0) return;
        amount = bound(amount, 1, balance);

        vm.prank(actor);
        vault.withdraw(amount);
        ghostWithdrawn += amount;
    }

    function togglePause(bool pause_) external {
        vm.prank(owner);
        if (pause_) vault.pause();
        else vault.unpause();
    }

    /// @dev ETH can be forced into any contract (selfdestruct, coinbase). The vault must stay solvent.
    function forceEth(uint256 amount) external {
        amount = bound(amount, 1, 10 ether);
        vm.deal(address(vault), address(vault).balance + amount);
        ghostForcedEth += amount;
    }

    function sumOfBalances() external view returns (uint256 sum) {
        for (uint256 i = 0; i < actors.length; i++) {
            sum += vault.balanceOf(actors[i]);
        }
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }
}

contract SafeVaultInvariantTest is Test {
    SafeVault internal vault;
    VaultHandler internal handler;
    address internal owner = makeAddr("owner");

    function setUp() public {
        vault = new SafeVault(owner);
        handler = new VaultHandler(vault, owner);
        targetContract(address(handler));
    }

    /// The vault always holds at least what it owes.
    function invariant_Solvent() public view {
        assertGe(address(vault).balance, vault.totalDeposits());
    }

    /// Per-account balances always sum to the global total.
    function invariant_AccountingMatches() public view {
        assertEq(handler.sumOfBalances(), vault.totalDeposits());
    }

    /// Total deposits equal everything put in minus everything taken out.
    function invariant_GhostAccounting() public view {
        assertEq(vault.totalDeposits(), handler.ghostDeposited() - handler.ghostWithdrawn());
        assertEq(
            address(vault).balance,
            handler.ghostDeposited() - handler.ghostWithdrawn() + handler.ghostForcedEth()
        );
    }

    /// No sequence of user actions can change the admin.
    function invariant_OwnerNeverChanges() public view {
        assertEq(vault.owner(), owner);
        assertEq(vault.pendingOwner(), address(0));
    }
}
