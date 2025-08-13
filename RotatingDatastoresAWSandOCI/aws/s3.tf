##########################################
# s3.tf
# Purpose: Create audit log bucket with versioning and cold storage
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Creates a dedicated S3 bucket for audit artifacts/logs.
# - Enables bucket versioning so every object write is retained as a new version.
# - Applies a lifecycle rule to transition objects immediately to
#   Glacier Instant Retrieval for cost-efficient retention.
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - Server-side encryption (SSE) is NOT explicitly configured in this PoC.
#   In production, enable SSE-KMS with a customer-managed CMK, e.g.:
#     resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
#       bucket = aws_s3_bucket.audit.id
#       rule {
#         apply_server_side_encryption_by_default {
#           sse_algorithm     = "aws:kms"
#           kms_master_key_id = aws_kms_key.secrets.arn
#         }
#       }
#     }
# - Consider enabling Object Lock (WORM) for compliance retention and
#   configure a retention policy as required by your auditors.
# - Ensure a Public Access Block is in place and a restrictive bucket policy
#   prevents public access (deny by default).
# - Follow least-privilege: the worker role should have only `s3:PutObject`
#   to this bucket (enforced in iam.tf), with no read/list unless required.


# Bucket to store audit records – must never contain plaintext secrets
resource "aws_s3_bucket" "audit" {
  bucket = "${var.name}-rotation-audit"
}

# Enable object versioning for tamper-evidence and recovery
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}

# Lifecycle: transition objects to Glacier IR immediately
resource "aws_s3_bucket_lifecycle_configuration" "glacier" {
  bucket = aws_s3_bucket.audit.id
  rule {
    id     = "archive-immediately"
    status = "Enabled"
    transition { days = 0 storage_class = "GLACIER_IR" }
  }
}
