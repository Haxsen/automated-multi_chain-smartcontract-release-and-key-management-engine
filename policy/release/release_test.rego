package release_test

import data.release

production_plan := {
	"schema": "release-engine/plan/v1",
	"profile": "mainnet",
	"production": true,
	"release": {"name": "safe-vault", "version": "1.0.0", "salt": "safe-vault/v1.0.0"},
	"signer": {"type": "kms", "key_id": "alias/web3-release-mainnet-deployer"},
	"owner": "0x1111111111111111111111111111111111111111",
	"expected_deployer": "0x2222222222222222222222222222222222222222",
	"secrets_source": "aws-secretsmanager",
	"verify_explorer": true,
	"require_clean_git": true,
	"require_tag": true,
	"git": {"commit": "abc", "dirty": false, "tag": "v1.0.0"},
	"guardrail_violations": [],
	"chains": [
		{"name": "ethereum", "chain_id": 1, "rpc_source": "secret", "max_gas_price_gwei": 30, "confirmations": 3},
		{"name": "arbitrum", "chain_id": 42161, "rpc_source": "secret", "max_gas_price_gwei": 0.5, "confirmations": 10},
		{"name": "optimism", "chain_id": 10, "rpc_source": "secret", "max_gas_price_gwei": 0.5, "confirmations": 5},
	],
}

with_patch(path, value) := json.patch(production_plan, [{"op": "replace", "path": path, "value": value}])

denied_with(plan, fragment) if {
	some msg in release.deny with input as plan
	contains(msg, fragment)
}

test_compliant_production_plan_passes if {
	count(release.deny) == 0 with input as production_plan
	count(release.warn) == 0 with input as production_plan
}

test_hot_key_in_production_is_denied if {
	denied_with(with_patch("/signer/type", "secretsmanager"), "non-exportable key")
}

test_anvil_on_public_chain_is_denied if {
	plan := json.patch(production_plan, [
		{"op": "replace", "path": "/production", "value": false},
		{"op": "replace", "path": "/signer/type", "value": "anvil"},
	])
	denied_with(plan, "must never target public chain ethereum")
}

test_dirty_tree_is_denied if {
	denied_with(with_patch("/git/dirty", true), "clean working tree")
}

test_unknown_tree_state_is_denied if {
	denied_with(with_patch("/git/dirty", null), "clean working tree")
}

test_wrong_tag_is_denied if {
	denied_with(with_patch("/git/tag", "v0.9.9"), "must be tagged v1.0.0")
}

test_deployer_owning_contracts_is_denied if {
	denied_with(with_patch("/owner", "0x2222222222222222222222222222222222222222"), "separation of duties")
}

test_missing_signer_pin_is_denied if {
	denied_with(with_patch("/expected_deployer", null), "pin expected_deployer")
}

test_literal_rpc_is_denied if {
	denied_with(with_patch("/chains/0/rpc_source", "literal"), "must be a secret reference")
}

test_shallow_confirmations_are_denied if {
	denied_with(with_patch("/chains/0/confirmations", 1), ">= 3 confirmations")
}

test_unverified_production_is_denied if {
	denied_with(with_patch("/verify_explorer", false), "source-verified")
}

test_salt_must_embed_version if {
	denied_with(with_patch("/release/salt", "safe-vault"), "must embed the release version")
}

test_engine_guardrail_violations_propagate if {
	denied_with(with_patch("/guardrail_violations", ["something bad"]), "engine guardrail: something bad")
}

test_duplicate_chain_ids_are_denied if {
	denied_with(with_patch("/chains/1/chain_id", 1), "duplicate chain ids")
}

test_break_glass_signer_warns_on_testnet if {
	plan := json.patch(production_plan, [
		{"op": "replace", "path": "/production", "value": false},
		{"op": "replace", "path": "/signer/type", "value": "secretsmanager"},
	])
	some msg in release.warn with input as plan
	contains(msg, "break-glass")
}
