package terraform_test

import data.terraform

good_signing_key := {"resource": {"aws_kms_key": {"deployer": [{
	"customer_master_key_spec": "ECC_SECG_P256K1",
	"key_usage": "SIGN_VERIFY",
	"deletion_window_in_days": 30,
	"policy": "${data.aws_iam_policy_document.deployer_key[each.key].json}",
}]}}}

test_good_signing_key_passes if {
	count(terraform.deny) == 0 with input as good_signing_key
}

test_wrong_curve_is_denied if {
	bad := json.patch(good_signing_key, [{"op": "replace", "path": "/resource/aws_kms_key/deployer/0/customer_master_key_spec", "value": "ECC_NIST_P256"}])
	some msg in terraform.deny with input as bad
	contains(msg, "secp256k1")
}

test_multi_region_signing_key_is_denied if {
	bad := json.patch(good_signing_key, [{"op": "add", "path": "/resource/aws_kms_key/deployer/0/multi_region", "value": true}])
	some msg in terraform.deny with input as bad
	contains(msg, "multi-region")
}

test_key_without_policy_is_denied if {
	bad := json.remove(good_signing_key, ["resource/aws_kms_key/deployer/0/policy"])
	some msg in terraform.deny with input as bad
	contains(msg, "explicit key policy")
}

test_symmetric_key_without_rotation_is_denied if {
	inp := {"resource": {"aws_kms_key": {"data": [{"policy": "x"}]}}}
	some msg in terraform.deny with input as inp
	contains(msg, "rotation")
}

test_short_deletion_window_is_denied if {
	bad := json.patch(good_signing_key, [{"op": "replace", "path": "/resource/aws_kms_key/deployer/0/deletion_window_in_days", "value": 7}])
	some msg in terraform.deny with input as bad
	contains(msg, "deletion window")
}

sign_statement(conditions) := {"data": {"aws_iam_policy_document": {"p": [{"statement": [{
	"sid": "Sign",
	"effect": "Allow",
	"actions": ["kms:Sign"],
	"resources": ["arn"],
	"condition": conditions,
}]}]}}}

test_sign_with_digest_and_algorithm_passes if {
	inp := sign_statement([
		{"test": "StringEquals", "variable": "kms:MessageType", "values": ["DIGEST"]},
		{"test": "StringEquals", "variable": "kms:SigningAlgorithm", "values": ["ECDSA_SHA_256"]},
	])
	count(terraform.deny) == 0 with input as inp
}

test_sign_without_message_type_is_denied if {
	inp := sign_statement([{"test": "StringEquals", "variable": "kms:SigningAlgorithm", "values": ["ECDSA_SHA_256"]}])
	some msg in terraform.deny with input as inp
	contains(msg, "DIGEST")
}

test_wildcard_actions_are_denied if {
	inp := {"data": {"aws_iam_policy_document": {"p": [{"statement": [{"sid": "Bad", "actions": ["kms:*"], "resources": ["*"]}]}]}}}
	some msg in terraform.deny with input as inp
	contains(msg, "wildcard action")
}

test_wildcard_deny_statements_are_fine if {
	inp := {"data": {"aws_iam_policy_document": {"p": [{"statement": [{"sid": "D", "effect": "Deny", "actions": ["s3:*"], "resources": ["*"]}]}]}}}
	count(terraform.deny) == 0 with input as inp
}

trust(test, sub) := {"data": {"aws_iam_policy_document": {"t": [{"statement": [{
	"sid": "Trust",
	"actions": ["sts:AssumeRoleWithWebIdentity"],
	"condition": [
		{"test": "StringEquals", "variable": "token.actions.githubusercontent.com:aud", "values": ["sts.amazonaws.com"]},
		{"test": test, "variable": "token.actions.githubusercontent.com:sub", "values": [sub]},
	],
}]}]}}}

test_exact_environment_subject_passes if {
	count(terraform.deny) == 0 with input as trust("StringEquals", "repo:acme/app:environment:mainnet")
}

test_wildcard_subject_is_denied if {
	some msg in terraform.deny with input as trust("StringLike", "repo:acme/*")
	contains(msg, "pin 'sub'")
}

test_secret_values_in_terraform_are_denied if {
	inp := {"resource": {"aws_secretsmanager_secret_version": {"v": [{"secret_string": "0xabc"}]}}}
	some msg in terraform.deny with input as inp
	contains(msg, "out-of-band")
}

test_secret_without_cmk_is_denied if {
	inp := {"resource": {"aws_secretsmanager_secret": {"s": [{"name": "x", "recovery_window_in_days": 30}]}}}
	some msg in terraform.deny with input as inp
	contains(msg, "customer-managed KMS key")
}

test_ledger_without_object_lock_is_denied if {
	inp := {"resource": {"aws_s3_bucket": {"ledger": [{"bucket": "x-deployment-ledger"}]}}}
	some msg in terraform.deny with input as inp
	contains(msg, "Object Lock")
}

test_force_destroy_is_denied if {
	inp := {"resource": {"aws_s3_bucket": {"b": [{"bucket": "logs", "force_destroy": true}]}}}
	some msg in terraform.deny with input as inp
	contains(msg, "force_destroy")
}
