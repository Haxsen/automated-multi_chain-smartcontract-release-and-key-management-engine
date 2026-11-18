// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {SafeVault} from "../src/SafeVault.sol";

/// @title Deploy
/// @notice Deterministic (CREATE2) release script driven by the release engine.
/// @dev - Every input comes from the environment, never from argv, so that no secret is
///        visible in the process list or CI logs.
///      - The signer is supplied by forge (`--aws` for AWS KMS, `--ledger`, `--unlocked`
///        for local anvil) or, for the Secrets Manager fallback, via DEPLOYER_PRIVATE_KEY.
///      - The same salt + init code yields the same address on every EVM chain, which makes
///        the release idempotent: if code already exists at the predicted address, the
///        script broadcasts nothing.
///      - The result is written as JSON to RELEASE_OUTPUT for the engine to consume.
contract Deploy is Script {
    struct Params {
        address owner;
        bytes32 salt;
        /// @dev address(0) disables the check.
        address expectedDeployer;
        /// @dev 0 means the signer is provided by forge (--aws / --ledger / --unlocked).
        uint256 deployerKey;
    }

    struct Result {
        address deployer;
        address vault;
        bool alreadyDeployed;
        bytes32 initCodeHash;
        bytes constructorArgs;
    }

    error DeployerMismatch(address expected, address actual);
    error AddressMismatch(address predicted, address actual);

    function run() external returns (Result memory result) {
        Params memory p = Params({
            owner: vm.envAddress("RELEASE_OWNER"),
            salt: keccak256(bytes(vm.envString("RELEASE_SALT"))),
            expectedDeployer: vm.envOr("EXPECTED_DEPLOYER", address(0)),
            deployerKey: vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0))
        });

        result = deploy(p);

        string memory outPath = vm.envOr("RELEASE_OUTPUT", string(""));
        if (bytes(outPath).length != 0) _writeOutput(result, p.salt, outPath);
    }

    function deploy(Params memory p) public returns (Result memory r) {
        r.deployer = p.deployerKey != 0 ? vm.addr(p.deployerKey) : msg.sender;
        if (p.expectedDeployer != address(0) && r.deployer != p.expectedDeployer) {
            revert DeployerMismatch(p.expectedDeployer, r.deployer);
        }

        r.constructorArgs = abi.encode(p.owner);
        r.initCodeHash =
            keccak256(abi.encodePacked(type(SafeVault).creationCode, r.constructorArgs));
        r.vault = computeCreate2Address(p.salt, r.initCodeHash);
        r.alreadyDeployed = r.vault.code.length != 0;

        if (r.alreadyDeployed) {
            console2.log("SafeVault already deployed, nothing to broadcast:", r.vault);
            return r;
        }

        if (p.deployerKey != 0) vm.startBroadcast(p.deployerKey);
        else vm.startBroadcast();
        SafeVault vault = new SafeVault{salt: p.salt}(p.owner);
        vm.stopBroadcast();

        if (address(vault) != r.vault) revert AddressMismatch(r.vault, address(vault));
        console2.log("SafeVault deployed:", r.vault);
    }

    function _writeOutput(Result memory r, bytes32 salt, string memory path) internal {
        string memory key = "release";
        vm.serializeAddress(key, "deployer", r.deployer);
        vm.serializeAddress(key, "vault", r.vault);
        vm.serializeBool(key, "alreadyDeployed", r.alreadyDeployed);
        vm.serializeBytes32(key, "initCodeHash", r.initCodeHash);
        vm.serializeBytes32(key, "salt", salt);
        vm.serializeUint(key, "chainId", block.chainid);
        string memory json = vm.serializeBytes(key, "constructorArgs", r.constructorArgs);
        vm.writeJson(json, path);
    }
}
