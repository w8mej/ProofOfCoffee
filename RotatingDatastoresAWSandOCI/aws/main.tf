##########################################
# main.tf
# Purpose: Configure provider & version
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Pins the AWS provider to a stable major version to ensure reproducible
#   and predictable behavior across Terraform runs.
# - Declares the AWS provider for use in this Terraform configuration.
#
# -----------------------------------------------------------------------------
# Ops notes
# -----------------------------------------------------------------------------
# - By default, the AWS region and profile are inherited from your local
#   environment variables or AWS CLI configuration. These can be overridden
#   in a `provider` block if needed.
# - In production, it is recommended to:
#     • Set an explicit `region` in the provider block to avoid accidental
#       deployments to the wrong AWS region.
#     • Use a remote backend (e.g., S3 with DynamoDB state locking) for
#       collaborative workflows, ensuring state consistency and preventing
#       concurrent modification issues.


terraform {
  required_providers { aws = { source = "hashicorp/aws" version = "~> 5.0" } }
}

# AWS provider configuration – region/profile from environment
provider "aws" {}
