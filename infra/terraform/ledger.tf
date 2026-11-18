# ─────────────────────────────────────────────────────────────────────────────
# Deployment ledger: append-only (WORM) record of every release manifest, signature
# bundle and JSONL log. S3 Object Lock means a compromised CI token - or an insider -
# cannot rewrite history to hide a malicious deployment.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "ledger" {
  #checkov:skip=CKV_AWS_18:Reads/writes are audited via CloudTrail S3 data events (org trail) instead of server access logs
  #checkov:skip=CKV_AWS_144:Single-region by default; add CRR to a second Object Lock bucket for disaster recovery
  #checkov:skip=CKV2_AWS_62:Writes come only from the release role and are already alerted via CloudTrail/EventBridge
  bucket              = "${var.name_prefix}-deployment-ledger-${local.account_id}"
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_versioning" "ledger" {
  bucket = aws_s3_bucket.ledger.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id

  rule {
    default_retention {
      mode = var.ledger_lock_mode
      days = var.ledger_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.ledger]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "ledger" {
  bucket                  = aws_s3_bucket.ledger.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ledger" {
  bucket = aws_s3_bucket.ledger.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "ledger" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.ledger.arn, "${aws_s3_bucket.ledger.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "AppendOnly"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"]
    resources = ["${aws_s3_bucket.ledger.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  statement {
    sid       = "DenyUnencryptedUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.ledger.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "ledger" {
  bucket = aws_s3_bucket.ledger.id
  policy = data.aws_iam_policy_document.ledger.json

  depends_on = [aws_s3_bucket_public_access_block.ledger]
}

resource "aws_s3_bucket_lifecycle_configuration" "ledger" {
  bucket = aws_s3_bucket.ledger.id

  rule {
    id     = "archive-old-records"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Locked objects stay immutable after transition; this only lowers storage cost.
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
  }

  depends_on = [aws_s3_bucket_versioning.ledger]
}
