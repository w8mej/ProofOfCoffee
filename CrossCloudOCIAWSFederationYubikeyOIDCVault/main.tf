########################################
# main.tf
# --------------------------------------
# This is the main infrastructure definition file.
# Implements:
#   - AWS & OCI providers
#   - Vault dynamic credentials retrieval
#   - KMS key management
#   - S3 buckets (source + destination) with encryption, logging, replication
#   - Lifecycle rules and notifications
#   - IAM role for S3 replication
# Security scanning reminder:
#   Run: 
#     docker run -t -v "./":/path checkmarx/kics scan -p /path -o "/path/"
#     docker run -t -v "./":/path tenable/terrascan scan -d /path
#     checkov -d ./
#     semgrep scan --config auto
########################################

########################################
# AWS Provider – source region
########################################
provider "aws" {
  region     = var.aws_region
  access_key = data.vault_aws_access_credentials.terraform.access_key
  secret_key = data.vault_aws_access_credentials.terraform.secret_key
  token      = data.vault_aws_access_credentials.terraform.security_token
}

########################################
# AWS Provider – destination region alias
########################################
provider "aws" {
  alias  = "dest"
  region = var.dest_region
}

########################################
# OCI Provider – credentials and token
########################################
provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
  auth_token       = data.vault_generic_secret.oci_token.data["token"]
}

########################################
# Vault dynamic AWS credentials
########################################
data "vault_aws_access_credentials" "terraform" {
  backend = vault_aws_secret_backend.aws.path
  role    = vault_aws_secret_backend_role.terraform.name
}

########################################
# Vault dynamic OCI token
########################################
data "vault_generic_secret" "oci_token" {
  path = "oci/token/terraform"
}

########################################
# AWS KMS Key for S3 source bucket encryption
########################################
resource "aws_kms_key" "demo" {
  description         = "KMS key for yubikey-crosscloud S3 bucket"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "Allow access to the key"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/some-iam-role" }
        Action    = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource  = "*"
      }
    ]
  })
}

########################################
# Destination region KMS key for S3 bucket encryption
########################################
resource "aws_kms_key" "dest_s3" {
  provider            = aws.dest
  description         = "CMK for destination S3 bucket encryption"
  enable_key_rotation = true
}

########################################
# Variable: dest_region
# Destination AWS region for replication
########################################
variable "dest_region" {
  type        = string
  description = "Destination AWS region for cross-region S3 replication (e.g., us-west-2)."

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d+$", var.dest_region))
    error_message = "dest_region must be a valid AWS region string (e.g., us-west-2)."
  }
}

########################################
# Destination bucket encryption configuration
########################################
resource "aws_s3_bucket_server_side_encryption_configuration" "demo_dest" {
  provider = aws.dest
  bucket   = aws_s3_bucket.demo_dest.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.dest_s3.arn
    }
  }
}

########################################
# Destination bucket public access block
########################################
resource "aws_s3_bucket_public_access_block" "demo_dest" {
  provider                = aws.dest
  bucket                  = aws_s3_bucket.demo_dest.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

########################################
# Destination bucket access logging
########################################
resource "aws_s3_bucket" "dest_logs" {
  provider = aws.dest
  bucket   = "yubikey-crosscloud-${random_id.suffix.hex}-dr-logs"
  acl      = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "demo_dest" {
  provider      = aws.dest
  bucket        = aws_s3_bucket.demo_dest.id
  target_bucket = aws_s3_bucket.dest_logs.id
  target_prefix = "logs/"
}

########################################
# Destination bucket (replication target)
########################################
resource "aws_s3_bucket" "demo_dest" {
  provider = aws.dest
  bucket   = "yubikey-crosscloud-${random_id.suffix.hex}-dr"
  acl      = "private"
}

resource "aws_s3_bucket_versioning" "demo_dest" {
  provider = aws.dest
  bucket   = aws_s3_bucket.demo_dest.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "dest_logs" {
  provider = aws.dest
  bucket   = aws_s3_bucket.demo_dest.id
  versioning_configuration { status = "Enabled" }
}

########################################
# Source bucket (versioned, encrypted, logging enabled)
########################################
resource "aws_s3_bucket" "demo" {
  bucket = "yubikey-crosscloud-${random_id.suffix.hex}"
  acl    = "private"

  versioning {
    enabled    = true
    mfa_delete = "Enabled"
  }

  logging {
    target_bucket = "target-bucket"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.demo.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

########################################
# IAM Role for S3 replication
########################################
resource "aws_iam_role" "s3_replication" {
  name = "yubikey-crosscloud-replication-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowS3ToAssume",
      Effect    = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  name = "yubikey-crosscloud-replication-policy"
  role = aws_iam_role.s3_replication.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"],
        Resource = aws_s3_bucket.demo.arn
      },
      {
        Effect   = "Allow",
        Action   = ["s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"],
        Resource = "${aws_s3_bucket.demo.arn}/*"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"],
        Resource = "${aws_s3_bucket.demo_dest.arn}/*"
      }
    ]
  })
}

########################################
# S3 Replication Configuration
########################################
resource "aws_s3_bucket_replication_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id
  role   = aws_iam_role.s3_replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.demo_dest.arn
      storage_class = "STANDARD"
      access_control_translation { owner = "Destination" }
    }
    delete_marker_replication { status = "Enabled" }
  }

  depends_on = [
    aws_s3_bucket_versioning.demo_src,
    aws_s3_bucket_versioning.demo_dest,
    aws_iam_role_policy.s3_replication
  ]
}

########################################
# Destination bucket lifecycle policy
########################################
resource "aws_s3_bucket_lifecycle_configuration" "demo_dest" {
  provider = aws.dest
  bucket   = aws_s3_bucket.demo_dest.id
  rule {
    id     = "default-lifecycle"
    status = "Enabled"
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
    transition { days = 30, storage_class = "STANDARD_IA" }
    noncurrent_version_expiration { noncurrent_days = 365 }
  }
}

#############################################
# Event notifications (✅ CKV2_AWS_62)
#############################################
# Topic in destination region
resource "aws_sns_topic" "s3_events_dest" {
  provider = aws.dest
  name     = "yubikey-crosscloud-s3-events-dest"
  # Optional: encrypt with KMS as well
  kms_master_key_id = aws_kms_key.dest_s3.arn
}

# Allow S3 (dest bucket) to publish to dest SNS
resource "aws_sns_topic_policy" "allow_s3_publish_dest" {
  provider = aws.dest
  arn      = aws_sns_topic.s3_events_dest.arn
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowS3Publish",
      Effect    = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action    = "SNS:Publish",
      Resource  = aws_sns_topic.s3_events_dest.arn,
      Condition = {
        ArnLike = { "aws:SourceArn" = aws_s3_bucket.demo_dest.arn }
      }
    }]
  })
}

resource "aws_s3_bucket_notification" "demo_dest" {
  provider = aws.dest
  bucket   = aws_s3_bucket.demo_dest.id

  topic {
    topic_arn = aws_sns_topic.s3_events_dest.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic_policy.allow_s3_publish_dest]
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- KMS: Vault + Key for CMK encryption ------------------------------

resource "oci_kms_vault" "audit_vault" {
  compartment_id = var.compartment_id
  display_name   = "tf-audit-vault"
  vault_type     = "DEFAULT" # or "VIRTUAL_PRIVATE"
}

# Management endpoint for keys in this vault
data "oci_kms_vault" "audit_vault" {
  vault_id = oci_kms_vault.audit_vault.id
}

resource "oci_kms_key" "audit_cmk" {
  compartment_id      = var.compartment_id
  display_name        = "tf-audit-cmk"
  management_endpoint = data.oci_kms_vault.audit_vault.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32 # 32 bytes = AES-256
  }
}

# Allow Object Storage (regional service principal) to use the key
# Replace <region> with your bucket region short name, e.g., "us-phoenix-1"
resource "oci_identity_policy" "objstore_use_kms" {
  compartment_id = var.compartment_id
  name           = "allow-objectstorage-use-audit-cmk"
  description    = "Let Object Storage use the KMS key for bucket encryption"

  statements = [
    "Allow service objectstorage-<region> to use keys in compartment id ${var.compartment_id}"
  ]
}

# --- Bucket: enable versioning, events, and CMK encryption -------------

resource "oci_objectstorage_bucket" "audit" {
  namespace          = data.oci_identity_tenancy.this.id
  name               = "audit-${random_id.suffix.hex}"
  compartment_id     = var.compartment_id
  public_access_type = "NoPublicAccess"

  # CKV_OCI_8
  versioning = "Enabled"

  # CKV_OCI_7
  object_events_enabled = true

  # CKV_OCI_9
  kms_key_id = oci_kms_key.audit_cmk.id
}

############################
# ✅ CKV2_AWS_62 – Notifications
############################

data "aws_caller_identity" "current" {}


# Reuse an existing CMK or create one just for SNS
resource "aws_kms_key" "sns" {
  description         = "CMK for SNS topic encryption"
  enable_key_rotation = true
}

resource "aws_sns_topic" "s3_events" {
  name              = "yubikey-crosscloud-s3-events"
  kms_master_key_id = aws_kms_key.sns.arn # ✅ encryption at rest
}

# Allow S3 to publish to the topic for this bucket
resource "aws_sns_topic_policy" "allow_s3_publish" {
  arn = aws_sns_topic.s3_events.arn
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowS3Publish",
      Effect    = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action    = "SNS:Publish",
      Resource  = aws_sns_topic.s3_events.arn,
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id },
        ArnLike      = { "aws:SourceArn" = aws_s3_bucket.demo.arn }
      }
    }]
  })
}

resource "aws_s3_bucket_notification" "demo" {
  bucket = aws_s3_bucket.demo.id

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events = [
      "s3:ObjectCreated:*",
      "s3:ObjectRemoved:*"
    ]
  }

  depends_on = [aws_sns_topic_policy.allow_s3_publish]
}

#################################
# ✅ CKV2_AWS_61 – Lifecycle rules
#################################
resource "aws_s3_bucket_lifecycle_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    id     = "default-lifecycle"
    status = "Enabled"

    # Clean up abandoned uploads
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Move objects to cheaper storage after 30 days
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # Expire noncurrent versions after 365 days (since versioning is enabled)
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}
