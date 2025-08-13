##########################################
# lambda.tf
# Purpose: Define the credential rotation Lambda using container image
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Deploys the rotation Lambda function from a pre-built container image
#   (image is built once and pushed to AWS ECR or Oracle OCIR).
# - Configures environment variables used by the Lambda worker to:
#     • Target both AWS RDS and OCI resources.
#     • Emit audit logs for credential rotation events.
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - No VPC configuration is included here. If the RDS instance is in a private
#   subnet, add `vpc_config` (subnets + security groups) and the corresponding
#   IAM permissions for Elastic Network Interfaces (ENIs).
# - `AUDIT_HASH_SALT_SSM` is currently passed as a string variable. In production,
#   source this value from AWS SSM Parameter Store (SecureString) or Secrets
#   Manager, and inject it at runtime to avoid hardcoding sensitive data.
# - Consider setting `reserved_concurrent_executions = 1` to prevent concurrent
#   rotations and avoid race conditions.
#
# -----------------------------------------------------------------------------
# Tunables
# -----------------------------------------------------------------------------
# - `timeout` and `memory_size` should be tuned based on expected network latency
#   and SSL handshake costs (e.g., Oracle TCPS + wallet operations may increase
#   execution time).
# - `image_uri` should be set in CI/CD pipelines to an immutable image tag
#   (such as a Git commit SHA) to ensure reproducible deployments.
###############################################



resource "aws_lambda_function" "rotate" {
  function_name = "${var.name}-rotate-credential"
  package_type  = "Image"           # Container image, not ZIP
  image_uri     = var.ecr_image_uri # Passed from CI/CD pipeline
  role          = aws_iam_role.lambda.arn
  timeout       = 120 # In seconds – enough for DB calls
  memory_size   = var.lambda_memory_mb

  environment {
    variables = {
      # Target systems for rotation
      TARGETS = "rds,oci"
      # AWS Secrets Manager IDs
      AWS_SECRET_ID           = aws_secretsmanager_secret.app_user.id
      AWS_CONN_BLOB_SECRET_ID = aws_secretsmanager_secret.connection_blob.id
      # OCI Secrets OCIDs
      OCI_SECRET_OCID           = var.oci_secret_ocid
      OCI_CONN_BLOB_SECRET_OCID = var.oci_conn_blob_secret_ocid
      # Logging & auditing
      LOG_BUCKET          = aws_s3_bucket.audit.bucket
      AUDIT_HASH_SALT_SSM = var.audit_hash_salt_ssm
      # RDS connection info
      RDS_ENGINE = var.rds_engine
      RDS_HOST   = var.rds_host
      RDS_DBNAME = var.rds_dbname
      RDS_PORT   = tostring(var.rds_port)
      # Rotation frequency
      ROTATION_MINUTES = "20"
    }
  }
}
