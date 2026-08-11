# ---------------------------------------------------------------------------
# Separate CMK for audit logs.
# The audit trail must survive compromise of what it audits.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "audit_key_policy" {

  statement {
    sid    = "EnableIAMPolicies"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # CloudTrail encrypts log files with this key before writing them.
  statement {
    sid    = "AllowCloudTrailEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

    # Scope to trails in this account only.
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  # Humans and Athena need to read the logs back. 
  # The lab operator needs to read logs back for verification and queries.
  statement {
    sid    = "AllowLogReaders"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "audit_logs" {
  description             = "CMK for CloudTrail audit logs (HIPAA lab 01)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.audit_key_policy.json

  tags = {
    Name         = "audit-logs-cmk"
    HIPAAControl = "164.312-b"
  }
}

resource "aws_kms_alias" "audit_logs" {
  name          = "alias/hipaa-lab01-audit-logs"
  target_key_id = aws_kms_key.audit_logs.key_id
}

# ---------------------------------------------------------------------------
# Bucket for the logs themselves.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "audit_logs" {
  bucket = "${var.bucket_prefix}-audit-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name         = "cloudtrail-audit-logs"
    HIPAAControl = "164.312-b"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit_logs.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# Bucket policy: CloudTrail is a service, not a user. It needs explicit
# permission to write here.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "audit_bucket_policy" {

  statement {
    sid    = "AllowCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit_logs.arn]
  }

  statement {
    sid    = "AllowCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.audit_logs.arn,
      "${aws_s3_bucket.audit_logs.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket     = aws_s3_bucket.audit_logs.id
  policy     = data.aws_iam_policy_document.audit_bucket_policy.json
  depends_on = [aws_s3_bucket_public_access_block.audit_logs]
}

# ---------------------------------------------------------------------------
# The trail.
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "phi_audit" {
  name           = "hipaa-lab01-phi-audit-trail"
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  kms_key_id     = aws_kms_key.audit_logs.arn

  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  # Management events: API calls that change configuration.
  # Free for the first trail.
  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # Management events: configuration changes AND all KMS key operations.
  # KMS Encrypt/Decrypt/GenerateDataKey are logged as management events,
  # not data events. Free for the first trail.
  advanced_event_selector {
    name = "PHI bucket object access"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.phi_landing_zone.arn}/"]
    }
  }
}