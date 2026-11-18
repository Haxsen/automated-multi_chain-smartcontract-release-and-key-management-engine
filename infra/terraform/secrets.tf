# ─────────────────────────────────────────────────────────────────────────────
# Release configuration secret (one per environment), a JSON object such as:
#   {
#     "SEPOLIA_RPC_URL": "https://eth-sepolia.g.alchemy.com/v2/...",
#     "ARBITRUM_SEPOLIA_RPC_URL": "...",
#     "OPTIMISM_SEPOLIA_RPC_URL": "...",
#     "ETHERSCAN_API_KEY": "...",
#     "DEPLOYER_PRIVATE_KEY": "0x..."   <- only for the break-glass profile
#   }
# Values are written out-of-band (aws secretsmanager put-secret-value) and are NEVER in
# Terraform code or state. The resource policy makes the secret write-only for humans:
# only the release role can read it.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "release" {
  #checkov:skip=CKV2_AWS_57:Holds third-party API keys (RPC provider, Etherscan) that a rotation Lambda cannot rotate; rotated manually per docs/runbook.md
  for_each = var.environments

  name                    = "${var.name_prefix}/${each.key}/config"
  description             = "RPC URLs and explorer API key for ${each.key} releases (JSON). Read-only to the release role."
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30

  tags = {
    Environment = each.key
  }
}

data "aws_iam_policy_document" "release_secret" {
  for_each = var.environments

  statement {
    sid       = "OnlyTheReleaseRoleMayRead"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.release[each.key].arn]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "release" {
  for_each = var.environments

  secret_arn          = aws_secretsmanager_secret.release[each.key].arn
  policy              = data.aws_iam_policy_document.release_secret[each.key].json
  block_public_policy = true
}
