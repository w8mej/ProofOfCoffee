###############################################################################
# Terraform & OCI Provider Configuration
#
# Purpose
# - Defines the Terraform version and OCI provider requirements for this
#   infrastructure.
# - Configures authentication to OCI tenancy for resource provisioning.
#
# Security & Ops
# - Pins OCI provider to `~> 7.13.0` for stability while allowing patch updates.
# - Requires Terraform >= 1.6.0 for consistent syntax and feature support.
# - Uses key-based authentication with:
#     • tenancy_ocid   → target OCI tenancy
#     • user_ocid      → OCI user API identity
#     • fingerprint    → public key fingerprint for auth
#     • private_key_path → path to private API key file
# - All authentication variables are passed via `var.*` inputs; never commit
#   credentials to source control.
# - Region is set via `var.region` to support multi-region deployments.
#
# Hardening
# - Ensure `private_key_path` points to a secure, least-privileged API key.
# - Use a dynamic group + instance principal auth for production to avoid static keys.
###############################################################################

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 7.13.0"
    }
  }
  required_version = ">= 1.6.0"
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}
