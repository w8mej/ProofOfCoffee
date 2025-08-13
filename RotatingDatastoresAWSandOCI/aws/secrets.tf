##########################################
# secrets.tf
# Purpose: Create Secrets Manager entries for credentials and connection info
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Creates two AWS Secrets Manager secrets:
#     1. multi-cloud/app_user — stores rotating credentials (username/password).
#     2. multi-cloud/app_connection_blob — stores DSNs & wallet pointer.
#       (Both updated atomically during rotation events.)
# - Enables multi-region replication for both secrets to reduce latency
#   for applications in other AWS regions.
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - This Terraform defines only the secret metadata.
#   It does NOT seed initial secret values; you must bootstrap them once
#   (e.g., via console, AWS CLI, or `aws_secretsmanager_put_secret_value`).
# - Replication ensures low-latency reads for multi-region apps; the rotation
#   Lambda should write only to the primary region secret and allow SM to replicate.
# - In production, consider adding resource-based policies for cross-account
#   read access if needed (but follow least-privilege principles).
#
# -----------------------------------------------------------------------------
# Tunables
# -----------------------------------------------------------------------------
# - You can attach fine-grained resource policies to allow specific principals
#   or AWS accounts to read these secrets across accounts.
# - Adjust replication region list to align with your application's footprint
#   and latency requirements.
#######################

# Rotating DB credential secret – multi-region replicated
resource "aws_secretsmanager_secret" "app_user" {
  name       = "multi-cloud/app_user"
  kms_key_id = aws_kms_key.secrets.arn

  # Multi-region replication – low-latency reads in other regions
  dynamic "replica" {
    for_each = toset(var.replica_regions)
    content { region = replica.value }
  }
}

# Rotating connection blob (DSN/wallet pointer) – updated atomically with app_user
resource "aws_secretsmanager_secret" "connection_blob" {
  name       = "multi-cloud/app_connection_blob"
  kms_key_id = aws_kms_key.secrets.arn

  dynamic "replica" {
    for_each = toset(var.replica_regions)
    content { region = replica.value }
  }
}
