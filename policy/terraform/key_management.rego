# METADATA
# title: Key-management infrastructure guardrails
# description: >-
#   Evaluated by conftest against the Terraform HCL (no AWS credentials or plan needed):
#   conftest test --parser hcl2 --policy policy/terraform --namespace terraform infra/terraform/*.tf
package terraform

# ─────────────────────────────── helpers ────────────────────────────────────

resources(type) := [[name, r] |
	some name
	some r in input.resource[type][name]
]

policy_statements := [[name, stmt] |
	some name
	some doc in input.data.aws_iam_policy_document[name]
	some stmt in doc.statement
]

is_allow(stmt) if object.get(stmt, "effect", "Allow") == "Allow"

wildcard_action(action) if action == "*"

wildcard_action(action) if endswith(action, ":*")

has_condition(stmt, variable, value) if {
	some c in stmt.condition
	c.variable == variable
	value in c.values
}

# ─────────────────────────────── KMS ────────────────────────────────────────

deny contains msg if {
	some [name, key] in resources("aws_kms_key")
	key.key_usage == "SIGN_VERIFY"
	key.customer_master_key_spec != "ECC_SECG_P256K1"
	msg := sprintf("aws_kms_key.%s: EVM signing keys must be ECC_SECG_P256K1 (secp256k1)", [name])
}

deny contains msg if {
	some [name, key] in resources("aws_kms_key")
	key.key_usage == "SIGN_VERIFY"
	key.multi_region == true
	msg := sprintf("aws_kms_key.%s: signing keys must not be multi-region (replicated key material)", [name])
}

deny contains msg if {
	some [name, key] in resources("aws_kms_key")
	not key.policy
	msg := sprintf("aws_kms_key.%s: an explicit key policy is required (no default 'root has kms:*')", [name])
}

deny contains msg if {
	some [name, key] in resources("aws_kms_key")
	object.get(key, "key_usage", "ENCRYPT_DECRYPT") == "ENCRYPT_DECRYPT"
	not key.enable_key_rotation == true
	msg := sprintf("aws_kms_key.%s: symmetric keys must enable automatic rotation", [name])
}

deny contains msg if {
	some [name, key] in resources("aws_kms_key")
	is_number(key.deletion_window_in_days)
	key.deletion_window_in_days < 14
	msg := sprintf("aws_kms_key.%s: deletion window must be >= 14 days", [name])
}

# Any statement that allows kms:Sign must pin the algorithm and require pre-hashed digests.
deny contains msg if {
	some [name, stmt] in policy_statements
	is_allow(stmt)
	"kms:Sign" in stmt.actions
	not has_condition(stmt, "kms:MessageType", "DIGEST")
	msg := sprintf("aws_iam_policy_document.%s (%s): kms:Sign must require kms:MessageType = DIGEST", [name, stmt.sid])
}

deny contains msg if {
	some [name, stmt] in policy_statements
	is_allow(stmt)
	"kms:Sign" in stmt.actions
	not has_condition(stmt, "kms:SigningAlgorithm", "ECDSA_SHA_256")
	msg := sprintf("aws_iam_policy_document.%s (%s): kms:Sign must pin kms:SigningAlgorithm", [name, stmt.sid])
}

# ─────────────────────────────── IAM ────────────────────────────────────────

deny contains msg if {
	some [name, stmt] in policy_statements
	is_allow(stmt)
	some action in stmt.actions
	wildcard_action(action)
	msg := sprintf("aws_iam_policy_document.%s (%s): wildcard action %q is not allowed", [name, stmt.sid, action])
}

deny contains msg if {
	some [name, stmt] in policy_statements
	"sts:AssumeRoleWithWebIdentity" in stmt.actions
	not exact_subject(stmt)
	msg := sprintf("aws_iam_policy_document.%s: OIDC trust must pin 'sub' with StringEquals and no wildcards", [name])
}

deny contains msg if {
	some [name, stmt] in policy_statements
	"sts:AssumeRoleWithWebIdentity" in stmt.actions
	not has_condition(stmt, "${local.github_oidc}:aud", "sts.amazonaws.com")
	not has_condition(stmt, "token.actions.githubusercontent.com:aud", "sts.amazonaws.com")
	msg := sprintf("aws_iam_policy_document.%s: OIDC trust must require aud = sts.amazonaws.com", [name])
}

exact_subject(stmt) if {
	some c in stmt.condition
	endswith(c.variable, ":sub")
	c.test == "StringEquals"
	every value in c.values {
		not contains(value, "*")
	}
}

deny contains msg if {
	some [name, role] in resources("aws_iam_role")
	is_number(role.max_session_duration)
	role.max_session_duration > 3600
	msg := sprintf("aws_iam_role.%s: release sessions must not exceed 1 hour", [name])
}

# ─────────────────────────────── Secrets ────────────────────────────────────

deny contains msg if {
	some [name, _] in resources("aws_secretsmanager_secret_version")
	msg := sprintf("aws_secretsmanager_secret_version.%s: secret values must be set out-of-band, never in Terraform (they would be stored in state)", [name])
}

deny contains msg if {
	some [name, secret] in resources("aws_secretsmanager_secret")
	not secret.kms_key_id
	msg := sprintf("aws_secretsmanager_secret.%s: must be encrypted with a customer-managed KMS key", [name])
}

deny contains msg if {
	some [name, secret] in resources("aws_secretsmanager_secret")
	is_number(secret.recovery_window_in_days)
	secret.recovery_window_in_days < 7
	msg := sprintf("aws_secretsmanager_secret.%s: recovery window must be >= 7 days", [name])
}

# ─────────────────────────────── S3 ledger ──────────────────────────────────

deny contains msg if {
	some [name, bucket] in resources("aws_s3_bucket")
	bucket.force_destroy == true
	msg := sprintf("aws_s3_bucket.%s: force_destroy would allow deleting audit records", [name])
}

deny contains msg if {
	some [name, bucket] in resources("aws_s3_bucket")
	contains(bucket.bucket, "ledger")
	not bucket.object_lock_enabled == true
	msg := sprintf("aws_s3_bucket.%s: the deployment ledger must have Object Lock (WORM) enabled", [name])
}
