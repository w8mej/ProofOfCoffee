##########################################
# variables.tf
# Purpose: Input variables for naming, infra config, and cross-cloud IDs
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Declares Terraform input variables for:
#     • Naming conventions
#     • Rotation cadence and dependencies
#     • Container image URI for the Lambda function
#     • Cross-cloud resource identifiers (AWS, OCI, etc.)
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - `audit_hash_salt_ssm` is a placeholder value.
#   In a production environment:
#     • Resolve this from AWS SSM Parameter Store (type: SecureString) or
#       AWS Secrets Manager at deploy time.
#     • Do NOT commit a literal salt value into source control.
#
# -----------------------------------------------------------------------------
# Tunables
# -----------------------------------------------------------------------------
# - Add `subnet_ids` and `security_group_ids` variables
#   if you intend to VPC-enable the Lambda for private RDS connectivity.
# - Expand with other environment-specific variables
#   for advanced deployments across multiple regions or clouds.

variable "name" {
  type    = string
  default = "rotator"
}

variable "replica_regions" {
  type    = list(string)
  default = ["us-east-1", "us-west-2"]
}

variable "ecr_image_uri" {
  type = string # ECR image URL built in CI
}

variable "rds_host" {
  type = string
}

variable "rds_dbname" {
  type = string
}

variable "audit_hash_salt_ssm" {
  type    = string
  default = "change-me" # Production: retrieve from SSM SecureString
}

# Cross-cloud linkage: OCI secret OCIDs for rotation in Oracle Autonomous DB
variable "oci_secret_ocid" {
  type = string
}

variable "oci_conn_blob_secret_ocid" {
  type = string
}

variable "rds_engine" {
  type    = string
  default = "postgres"

  validation {
    condition     = contains(["postgres", "mysql"], var.rds_engine)
    error_message = "rds_engine must be one of: postgres, mysql."
  }
}

variable "rds_port" {
  type    = number
  default = 5432

  validation {
    condition     = var.rds_port > 0 && var.rds_port < 65536
    error_message = "rds_port must be a valid TCP port (1–65535)."
  }
}

variable "lambda_memory_mb" {
  type    = number
  default = 512

  validation {
    # Lambda allows 128–10240 MB in 1 MB increments; constrain if you like.
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 10240
    error_message = "lambda_memory_mb must be between 128 and 10240."
  }
}
