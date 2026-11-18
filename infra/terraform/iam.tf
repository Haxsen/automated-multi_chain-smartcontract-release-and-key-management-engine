# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions -> AWS via OIDC. No long-lived AWS credentials exist anywhere.
# One role per environment; each role can only be assumed by a job that is bound to the
# matching GitHub Environment, whose protection rules (required reviewers, tag-only
# deployments) therefore gate every signature.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  account_id     = data.aws_caller_identity.current.account_id
  partition      = data.aws_partition.current.partition
  github_oidc    = "token.actions.githubusercontent.com"
  key_admin_arns = length(var.key_admin_arns) > 0 ? var.key_admin_arns : ["arn:${local.partition}:iam::${local.account_id}:root"]
  github_oidc_arn = (
    var.create_github_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : data.aws_iam_openid_connect_provider.github[0].arn
  )
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://${local.github_oidc}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://${local.github_oidc}"
}

data "aws_iam_policy_document" "release_trust" {
  for_each = var.environments

  statement {
    sid     = "GitHubEnvironmentOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact match - no wildcards: a fork, another repo, a PR or a job outside this
    # environment cannot obtain a token that satisfies this.
    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc}:sub"
      values   = ["repo:${var.github_repository}:environment:${each.key}"]
    }
  }
}

resource "aws_iam_role" "release" {
  for_each = var.environments

  name                 = "${var.name_prefix}-${each.key}-release"
  description          = "Assumed by GitHub Actions (${each.key} environment) to sign contract deployments"
  assume_role_policy   = data.aws_iam_policy_document.release_trust[each.key].json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "release_permissions" {
  for_each = var.environments

  statement {
    sid       = "SignDeploymentDigestsOnly"
    effect    = "Allow"
    actions   = ["kms:Sign"]
    resources = [aws_kms_key.deployer[each.key].arn]

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["ECDSA_SHA_256"]
    }

    # Ethereum signs keccak256 digests; never let KMS hash (or sign) raw messages.
    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }
  }

  statement {
    sid       = "DeriveDeployerAddress"
    effect    = "Allow"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = [aws_kms_key.deployer[each.key].arn]
  }

  statement {
    sid       = "ReadReleaseConfigSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.release[each.key].arn]
  }

  statement {
    sid       = "DecryptOnlyViaSecretsManager"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:SecretARN"
      values   = [aws_secretsmanager_secret.release[each.key].arn]
    }
  }

  statement {
    sid       = "AppendToDeploymentLedger"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.ledger.arn}/${each.key}/*"]
  }

  statement {
    sid       = "EncryptLedgerObjectsViaS3"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = [aws_kms_key.data.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "release" {
  for_each = var.environments

  name   = "release-least-privilege"
  role   = aws_iam_role.release[each.key].id
  policy = data.aws_iam_policy_document.release_permissions[each.key].json
}
