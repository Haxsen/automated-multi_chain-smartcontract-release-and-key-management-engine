output "github_environment_variables" {
  description = <<-EOT
    Configure these as GitHub Environment *variables* (Settings -> Environments -> <env>).
    None of them is a secret: they are identifiers that are useless without the OIDC trust.
    Also set RELEASE_OWNER (your Safe multisig) and EXPECTED_DEPLOYER (from `deployer_address_hint`).
  EOT
  value = {
    for env in keys(var.environments) : env => {
      AWS_REGION               = var.aws_region
      AWS_RELEASE_ROLE_ARN     = aws_iam_role.release[env].arn
      AWS_KMS_KEY_ID           = aws_kms_alias.deployer[env].arn
      RELEASE_SECRET_ID        = aws_secretsmanager_secret.release[env].name
      DEPLOYMENT_LEDGER_BUCKET = aws_s3_bucket.ledger.bucket
    }
  }
}

output "deployer_address_hint" {
  description = "Derive each deployer's EVM address (needs kms:GetPublicKey)."
  value = {
    for env in keys(var.environments) :
    env => "AWS_KMS_KEY_ID=${aws_kms_alias.deployer[env].arn} cast wallet address --aws"
  }
}

output "security_alerts_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}
