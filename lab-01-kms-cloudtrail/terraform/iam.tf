# ---------------------------------------------------------------------------
# Data source: who am I?
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Trust policy shared by all three lab roles.
#
# In production these would be assumed by services (EC2 instance profiles,
# ECS task roles, Lambda execution roles). For the lab, the admin user
# assumes them directly so we can test each identity by hand.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "lab_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }
  }
}

# ---------------------------------------------------------------------------
# Role 1: ingestion. Writes 837P files into the landing zone.
# Needs to encrypt, must NOT be able to read anything back.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "claims_ingestion" {
  name               = "hipaa-lab01-claims-ingestion"
  assume_role_policy = data.aws_iam_policy_document.lab_assume_role.json
  description        = "Writes 837P claim extracts to the PHI landing zone."
}

# ---------------------------------------------------------------------------
# Role 2: processing. Reads 837P files for downstream warehouse load.
# Needs to decrypt.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "claims_processing" {
  name               = "hipaa-lab01-claims-processing"
  assume_role_policy = data.aws_iam_policy_document.lab_assume_role.json
  description        = "Reads 837P claim extracts for warehouse processing"
}

# ---------------------------------------------------------------------------
# Role 3: the negative test. Exists to be denied.
# An analyst role with S3 access but no KMS grant — proves that bucket
# permissions alone are not enough to read encrypted PHI.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "unauthorized_analyst" {
  name               = "hipaa-lab01-unauthorized-analyst"
  assume_role_policy = data.aws_iam_policy_document.lab_assume_role.json
  description        = "Analyst role with S3 access but no KMS grant"
}