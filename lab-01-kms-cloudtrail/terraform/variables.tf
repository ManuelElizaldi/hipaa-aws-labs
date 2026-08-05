variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment tag applied to all resources"
  type        = string
  default     = "lab"
}

variable "bucket_prefix" {
  description = "Prefix for the S3 bucket names (must be globally unique when combined with suffix)"
  type        = string
  default     = "hipaa-lab01"
}