# ─────────────────────────────────────────────────────────────────────────────
# Detection. Deployments are rare, so every signature is worth a notification, and any
# change to a key, its policy or the release secret is a potential incident.
# Requires a CloudTrail trail recording management events in this region (most
# organisations already have an org-wide trail).
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.name_prefix}-security-alerts"
  kms_master_key_id = aws_kms_key.data.id
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == null ? 0 : 1

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  deployer_key_arns = [for k in aws_kms_key.deployer : k.arn]

  alert_rules = {
    deployer-key-signing = {
      description = "Informational: a deployer key signed a transaction"
      pattern = {
        source        = ["aws.kms"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["kms.amazonaws.com"]
          eventName   = ["Sign"]
          resources   = { ARN = local.deployer_key_arns }
        }
      }
    }

    deployer-key-tampering = {
      description = "CRITICAL: deployer key disabled, scheduled for deletion, re-policied or granted"
      pattern = {
        source        = ["aws.kms"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["kms.amazonaws.com"]
          eventName = [
            "DisableKey", "ScheduleKeyDeletion", "PutKeyPolicy", "CreateGrant",
            "UpdateAlias", "DeleteAlias", "ImportKeyMaterial",
          ]
          resources = { ARN = local.deployer_key_arns }
        }
      }
    }

    release-secret-changes = {
      description = "HIGH: a release secret value or its resource policy changed"
      pattern = {
        source        = ["aws.secretsmanager"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["secretsmanager.amazonaws.com"]
          eventName = [
            "PutSecretValue", "UpdateSecret", "DeleteSecret",
            "PutResourcePolicy", "DeleteResourcePolicy", "RestoreSecret",
          ]
          requestParameters = {
            secretId = [
              { prefix = "${var.name_prefix}/" },
              { prefix = "arn:${local.partition}:secretsmanager:${var.aws_region}:${local.account_id}:secret:${var.name_prefix}/" },
            ]
          }
        }
      }
    }

    release-role-trust-changes = {
      description = "CRITICAL: the trust or permissions of a release role changed"
      pattern = {
        source        = ["aws.iam"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName = [
            "UpdateAssumeRolePolicy", "PutRolePolicy", "AttachRolePolicy",
            "DeleteRolePolicy", "DetachRolePolicy",
          ]
          requestParameters = { roleName = [for r in aws_iam_role.release : r.name] }
        }
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "alerts" {
  for_each = local.alert_rules

  name          = "${var.name_prefix}-${each.key}"
  description   = each.value.description
  event_pattern = jsonencode(each.value.pattern)
}

resource "aws_cloudwatch_event_target" "alerts" {
  for_each = local.alert_rules

  rule = aws_cloudwatch_event_rule.alerts[each.key].name
  arn  = aws_sns_topic.security_alerts.arn
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid       = "EventBridgeRulesMayPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for r in aws_cloudwatch_event_rule.alerts : r.arn]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}
