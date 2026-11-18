# ─────────────────────────────────────────────────────────────────────────────
# Deployer keys: secp256k1 private keys generated inside AWS KMS HSMs (FIPS 140-3 L3).
# They are non-exportable - no human, CI runner or log can ever see them. The key policy
# makes the environment's release role the ONLY principal that can sign, and gives key
# administrators everything except signing (separation of duties).
#
# Asymmetric KMS keys cannot be auto-rotated. Rotation = new key -> new deployer address
# -> update EXPECTED_DEPLOYER (see docs/runbook.md). Contract ownership is held by a
# multisig, never by the deployer, so rotating the deployer never touches live contracts.
# ─────────────────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "deployer_key" {
  #checkov:skip=CKV_AWS_111:Key policy - "*" resource means "this key" and is mandatory in KMS key policies
  #checkov:skip=CKV_AWS_109:Key policy - admins need PutKeyPolicy; tampering is alerted on (monitoring.tf)
  #checkov:skip=CKV_AWS_356:Key policy - "*" resource means "this key" and is mandatory in KMS key policies
  for_each = var.environments

  statement {
    sid    = "KeyAdministrationWithoutUsage"
    effect = "Allow"
    actions = [
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:GetPublicKey",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateAlias",
      "kms:UpdateKeyDescription",
    ]
    resources = ["*"] # in a key policy "*" means "this key"

    principals {
      type        = "AWS"
      identifiers = local.key_admin_arns
    }
  }

  statement {
    sid       = "ReleaseRoleSignsDigests"
    effect    = "Allow"
    actions   = ["kms:Sign"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.release[each.key].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:SigningAlgorithm"
      values   = ["ECDSA_SHA_256"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:MessageType"
      values   = ["DIGEST"]
    }
  }

  statement {
    sid       = "ReleaseRoleReadsPublicKey"
    effect    = "Allow"
    actions   = ["kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.release[each.key].arn]
    }
  }

  # Belt and braces: even if someone later attaches an IAM policy granting kms:Sign or
  # creates a grant, an explicit Deny in the key policy wins.
  statement {
    sid       = "NobodyElseMaySignOrGrant"
    effect    = "Deny"
    actions   = ["kms:Sign", "kms:CreateGrant"]
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

resource "aws_kms_key" "deployer" {
  for_each = var.environments

  description              = "EVM deployer key (${each.key}): secp256k1, sign-only, non-exportable"
  customer_master_key_spec = "ECC_SECG_P256K1"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = each.value.deletion_window_days
  multi_region             = false
  policy                   = data.aws_iam_policy_document.deployer_key[each.key].json

  tags = {
    Environment = each.key
    Purpose     = "evm-deployer"
  }
}

resource "aws_kms_alias" "deployer" {
  for_each = var.environments

  name          = "alias/${var.name_prefix}-${each.key}-deployer"
  target_key_id = aws_kms_key.deployer[each.key].key_id
}

# ─────────────────────────────────────────────────────────────────────────────
# Data key: symmetric CMK (auto-rotated) encrypting the release secrets, the deployment
# ledger and the alert topic. Usage is only possible *through* those AWS services.
# ─────────────────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "data_key" {
  #checkov:skip=CKV_AWS_111:Key policy - "*" resource means "this key" and is mandatory in KMS key policies
  #checkov:skip=CKV_AWS_109:Key policy - admins need PutKeyPolicy; usage is constrained by kms:ViaService
  #checkov:skip=CKV_AWS_356:Key policy - "*" resource means "this key" and is mandatory in KMS key policies
  statement {
    sid    = "KeyAdministration"
    effect = "Allow"
    actions = [
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListResourceTags",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:UpdateAlias",
      "kms:UpdateKeyDescription",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.key_admin_arns
    }
  }

  statement {
    sid       = "AccountPrincipalsViaSecretsManagerAndS3"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "secretsmanager.${var.aws_region}.amazonaws.com",
        "s3.${var.aws_region}.amazonaws.com",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "EventBridgePublishesEncryptedAlerts"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${var.name_prefix}: encrypts release secrets, deployment ledger and alerts"
  enable_key_rotation     = true
  rotation_period_in_days = 90
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.data_key.json
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}
