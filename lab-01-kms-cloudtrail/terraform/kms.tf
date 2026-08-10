# ---------------------------------------------------------------------------
# Key policy for the PHI landing zone CMK.
#
# KMS key policies are the ROOT of authorization. A principal not permitted
# here cannot use this key regardless of its IAM permissions.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "phi_key_policy" {

  # -- Statement 1: delegate authorization to IAM -----------------------------
  # Without this, the key is orphaned and unrecoverable. "root" here means
  # the ACCOUNT, not the root user.
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

  # -- Statement 2: ingestion may encrypt, never decrypt ----------------------
  # GenerateDataKey is the write path under envelope encryption.
  # Decrypt is deliberately absent: a compromised ingestion service
  # cannot read back the claims history it wrote.
  statement {
    sid    = "AllowIngestionEncrypt"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.claims_ingestion.arn]
    }

    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }

  # -- Statement 3: processing may decrypt ------------------------------------
  statement {
    sid    = "AllowProcessingDecrypt"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.claims_processing.arn]
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# The customer-managed key itself.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "phi_landing_zone" {
  description = "CMK for 837P claim extracts in the PHI landing zone (HIPAA lab 01)"

  # Annual automatic rotation. HIPAA does not mandate a rotation interval,
  # but rotation limits the volume of data protected by any single key.
  enable_key_rotation = true

  # 7 days is the minimum AWS allows. Default is 30.
  # Short window keeps lab teardown cheap; production would use 30
  # so an accidental deletion has a real recovery period.
  deletion_window_in_days = 7

  policy = data.aws_iam_policy_document.phi_key_policy.json

  tags = {
    Name         = "phi-landing-zone-cmk"
    HIPAAControl = "164.312-a-2-iv"
    DataClass    = "phi-simulated"
  }
}

# ---------------------------------------------------------------------------
# A human-readable alias. Without one, you reference keys by UUID forever.
# ---------------------------------------------------------------------------
resource "aws_kms_alias" "phi_landing_zone" {
  name          = "alias/hipaa-lab01-phi-landing-zone"
  target_key_id = aws_kms_key.phi_landing_zone.key_id
}