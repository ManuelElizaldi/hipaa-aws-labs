# ---------------------------------------------------------------------------
# The PHI landing zone bucket.
# Account ID suffix guarantees the globally unique name S3 requires.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "phi_landing_zone" {
  bucket = "${var.bucket_prefix}-phi-landing-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name         = "phi-landing-zone"
    HIPAAControl = "164.312-a-2-iv"
  }
}

# ---------------------------------------------------------------------------
# Default encryption: objects uploaded without encryption headers get the CMK.
# A fallback, not an enforcement. The bucket policy does the enforcing.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_server_side_encryption_configuration" "phi_landing_zone" {
  bucket = aws_s3_bucket.phi_landing_zone.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.phi_landing_zone.arn
      sse_algorithm     = "aws:kms"
    }
    # Reuses one data key for many objects in the same bucket, cutting
    # KMS API calls (and cost) substantially at real volume.
    bucket_key_enabled = true
  }
}

# ---------------------------------------------------------------------------
# No public access, ever. All four settings on.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_public_access_block" "phi_landing_zone" {
  bucket = aws_s3_bucket.phi_landing_zone.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Versioning: deleted or overwritten objects are recoverable.
# Relevant to HIPAA integrity requirements, 164.312(c)(1).
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_versioning" "phi_landing_zone" {
  bucket = aws_s3_bucket.phi_landing_zone.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# Bucket policy: three denials.
# Deny always wins over Allow in IAM evaluation, so these are absolute.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "phi_bucket_policy" {

  # Reject uploads that are not SSE-KMS.
  statement {
    sid    = "DenyNonKMSUploads"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.phi_landing_zone.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  # Reject uploads using any KMS key other than ours.
  statement {
    sid    = "DenyWrongKMSKey"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.phi_landing_zone.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.phi_landing_zone.arn]
    }
  }

  # Reject any request not over TLS. Maps to 164.312(e)(1), transmission security.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.phi_landing_zone.arn,
      "${aws_s3_bucket.phi_landing_zone.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "phi_landing_zone" {
  bucket = aws_s3_bucket.phi_landing_zone.id
  policy = data.aws_iam_policy_document.phi_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.phi_landing_zone]
}

# ---------------------------------------------------------------------------
# Role permissions on S3.
#
# Note: processing and analyst get IDENTICAL S3 permissions.
# The only difference between them lives in the KMS key policy.
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "ingestion_s3" {
  name = "s3-write"
  role = aws_iam_role.claims_ingestion.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = "${aws_s3_bucket.phi_landing_zone.arn}/*"
    }]
  })
}

resource "aws_iam_role_policy" "processing_s3" {
  name = "s3-read"
  role = aws_iam_role.claims_processing.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.phi_landing_zone.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.phi_landing_zone.arn
      },
    ]
  })
}

resource "aws_iam_role_policy" "analyst_s3" {
  name = "s3-read"
  role = aws_iam_role.unauthorized_analyst.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.phi_landing_zone.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.phi_landing_zone.arn
      },
    ]
  })
}