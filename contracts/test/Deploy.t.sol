// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {SafeVault} from "../src/SafeVault.sol";

/// @dev Tests the release script itself: determinism, idempotency and signer pinning.
contract DeployScriptTest is Test {
    Deploy internal script;
    address internal owner = makeAddr("multisig-owner");
    uint256 internal deployerKey = 0xA11CE;
    address internal deployer;
    bytes32 internal constant SALT = keccak256("safe-vault/v1.0.0");

    function setUp() public {
        script = new Deploy();
        deployer = vm.addr(deployerKey);
        vm.deal(deployer, 1 ether);
    }

    function _params() internal view returns (Deploy.Params memory) {
        return Deploy.Params({
            owner: owner, salt: SALT, expectedDeployer: deployer, deployerKey: deployerKey
        });
    }

    function test_Deploy_SetsConfiguredOwnerNotDeployer() public {
        Deploy.Result memory r = script.deploy(_params());

        assertFalse(r.alreadyDeployed);
        assertEq(r.deployer, deployer);
        assertGt(r.vault.code.length, 0);
        assertEq(SafeVault(payable(r.vault)).owner(), owner);
        assertEq(r.constructorArgs, abi.encode(owner));
    }

    function test_Deploy_SameAddressOnEveryChain() public {
        uint256 snapshot = vm.snapshotState();

        vm.chainId(1); // Ethereum
        address onEthereum = script.deploy(_params()).vault;
        vm.revertToState(snapshot);

        vm.chainId(42_161); // Arbitrum One
        address onArbitrum = script.deploy(_params()).vault;
        vm.revertToState(snapshot);

        vm.chainId(10); // OP Mainnet
        address onOptimism = script.deploy(_params()).vault;

        assertEq(onEthereum, onArbitrum);
        assertEq(onEthereum, onOptimism);
    }

    function test_Deploy_IsIdempotent() public {
        Deploy.Result memory first = script.deploy(_params());
        uint64 nonceBefore = vm.getNonce(deployer);

        Deploy.Result memory second = script.deploy(_params());

        assertTrue(second.alreadyDeployed);
        assertEq(second.vault, first.vault);
        assertEq(vm.getNonce(deployer), nonceBefore, "re-run must not send a transaction");
    }

    function test_Deploy_RevertsOnUnexpectedDeployer() public {
        Deploy.Params memory p = _params();
        p.expectedDeployer = makeAddr("pinned-kms-address");

        vm.expectRevert(
            abi.encodeWithSelector(Deploy.DeployerMismatch.selector, p.expectedDeployer, deployer)
        );
        script.deploy(p);
    }

    function test_Deploy_DifferentSaltDifferentAddress() public {
        address a = script.deploy(_params()).vault;

        Deploy.Params memory p = _params();
        p.salt = keccak256("safe-vault/v1.0.1");
        address b = script.deploy(p).vault;

        assertTrue(a != b);
    }

    function test_Deploy_DifferentOwnerDifferentAddress() public {
        // A front-runner who replays our init code can only ever deploy a vault owned by us.
        // Changing the owner changes the address, so the address cannot be squatted.
        address a = script.deploy(_params()).vault;

        Deploy.Params memory p = _params();
        p.owner = makeAddr("attacker");
        address b = script.deploy(p).vault;

        assertTrue(a != b);
    }
}
