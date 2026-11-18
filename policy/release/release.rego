# METADATA
# title: Release plan gate
# description: >-
#   Evaluated on `release-engine plan` output BEFORE any secret is fetched or any key is used:
#   conftest test --policy policy/release --namespace release plan.json
package release

local_chain_ids := {31337, 31338, 31339, 1337}

hardware_signers := {"kms", "ledger"}

semver := `^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`

missing(value) if value == null

missing(value) if value == ""

# ─────────────────────────────── every profile ──────────────────────────────

deny contains msg if {
	input.schema != "release-engine/plan/v1"
	msg := sprintf("unsupported plan schema %v", [input.schema])
}

deny contains msg if {
	some violation in object.get(input, "guardrail_violations", [])
	msg := sprintf("engine guardrail: %s", [violation])
}

deny contains msg if {
	input.signer.type == "anvil"
	some chain in input.chains
	not chain.chain_id in local_chain_ids
	msg := sprintf("dev signer 'anvil' must never target public chain %s (%d)", [chain.name, chain.chain_id])
}

deny contains msg if {
	not regex.match(semver, input.release.version)
	msg := sprintf("release version %q is not semver", [input.release.version])
}

# A version bump must yield a new CREATE2 address, never collide with the old release.
deny contains msg if {
	not contains(input.release.salt, input.release.version)
	msg := sprintf("CREATE2 salt %q must embed the release version %s", [input.release.salt, input.release.version])
}

deny contains msg if {
	some chain in input.chains
	chain.max_gas_price_gwei <= 0
	msg := sprintf("%s: a positive gas price ceiling is required", [chain.name])
}

deny contains msg if {
	count({c.chain_id | some c in input.chains}) != count(input.chains)
	msg := "duplicate chain ids in one release"
}

# ─────────────────────────────── production ─────────────────────────────────

deny contains msg if {
	input.production
	not input.signer.type in hardware_signers
	msg := sprintf("production must sign with a non-exportable key (kms/ledger), not %q", [input.signer.type])
}

deny contains msg if {
	input.production
	input.secrets_source != "aws-secretsmanager"
	msg := "production secrets must come from AWS Secrets Manager"
}

deny contains msg if {
	input.production
	some chain in input.chains
	chain.rpc_source != "secret"
	msg := sprintf("%s: production RPC URL must be a secret reference", [chain.name])
}

deny contains msg if {
	input.production
	some chain in input.chains
	chain.chain_id in local_chain_ids
	msg := sprintf("%s: local chain in a production release", [chain.name])
}

deny contains msg if {
	input.production
	some chain in input.chains
	chain.confirmations < 3
	msg := sprintf("%s: production needs >= 3 confirmations (got %d)", [chain.name, chain.confirmations])
}

deny contains msg if {
	input.production
	not input.verify_explorer
	msg := "production releases must be source-verified on the explorer"
}

deny contains msg if {
	input.production
	not input.require_tag
	msg := "production profile must set require_tag"
}

deny contains msg if {
	input.production
	input.git.dirty != false
	msg := "production releases must be built from a clean working tree"
}

deny contains msg if {
	input.production
	input.git.tag != sprintf("v%s", [input.release.version])
	msg := sprintf("production HEAD must be tagged v%s (found %v)", [input.release.version, input.git.tag])
}

deny contains msg if {
	input.production
	missing(input.expected_deployer)
	msg := "production must pin expected_deployer to the KMS-derived address"
}

deny contains msg if {
	input.production
	lower(input.owner) == lower(input.expected_deployer)
	msg := "separation of duties: the deployer key must not own the contracts"
}

# ─────────────────────────────── warnings ───────────────────────────────────

warn contains msg if {
	input.signer.type == "secretsmanager"
	msg := "break-glass hot key in use - rotate DEPLOYER_PRIVATE_KEY after this release"
}

warn contains msg if {
	not input.production
	not input.require_clean_git
	some chain in input.chains
	not chain.chain_id in local_chain_ids
	msg := sprintf("%s: public-chain release without require_clean_git", [chain.name])
}
