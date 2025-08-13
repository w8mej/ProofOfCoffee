##########################################
# kms.tf
# Purpose: Create a CMK for encrypting Secrets Manager data
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Creates a KMS Customer Managed Key (CMK) intended for encrypting
#   AWS Secrets Manager secrets.
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - In production, set enable_key_rotation = true to enable annual automatic
#   rotation of the CMK.
# - Add a restrictive key policy to limit both administrative and usage
#   permissions to authorized principals only.
# - Ensure Secrets Manager secrets actually reference this CMK for encryption.
#   (In this PoC, they do via `kms_key_id` in `secrets.tf`.)

resource "aws_kms_key" "secrets" {
  description             = "KMS for Secrets Manager (rotation)"
  deletion_window_in_days = 30 # Safety period before deletion
  # Production: enable_key_rotation = true and set strict key policy
}

