provider "aws" {
  region  = var.aws_region
  profile = "hipaa-labs"

  default_tags {
    tags = local.common_tags
  }
}

locals {
  common_tags = {
    Project     = "hipaa-aws-labs"
    Lab         = "lab-01-kms-cloudtrail"
    Environment = var.environment
    ManagedBy   = "terraform"
    DataClass   = "phi-simulated"
  }
}
