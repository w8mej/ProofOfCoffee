##########################################
# iam.tf
# Purpose: Define least-privilege IAM role & policy for Lambda
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Creates an IAM role for the Lambda with a trust policy for
#   "lambda.amazonaws.com".
# - Attaches an inline policy that allows:
#     * Read/Write to AWS Secrets Manager for two specific secrets
#       (credential + connection blob).
#     * Write access to the S3 audit bucket.
#     * Emitting CloudWatch Logs (create group/stream + put events).
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - No KMS API permissions are granted here because Secrets Manager encrypts
#   with KMS on the service side. If you later use SSE-KMS on S3 or
#   customer-managed CMKs for SM data key APIs, add explicit kms:Encrypt /
#   kms:Decrypt permissions on that CMK.
# - Wildcards are avoided for Secrets Manager and S3 resource ARNs for better
#   auditability. Keep it that way.
#
# -----------------------------------------------------------------------------
# Tunables
# -----------------------------------------------------------------------------
# - Add s3:GetObject only if the worker must read objects (not needed now).
# - Add required ec2:* permissions only if you VPC-enable the Lambda
#   (not present in this PoC).



# Trust policy: Allows Lambda service to assume this role
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["lambda.amazonaws.com"] }
  }
}

# IAM role for the Lambda function
resource "aws_iam_role" "lambda" {
  name               = "${var.name}-rotate-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

# Inline policy: grant explicit permissions to rotate secrets, log to CWL, and write audit logs to S3
data "aws_iam_policy_document" "lambda_policy" {
  # Secrets Manager permissions – restricted to two specific secrets and their versions
  statement {
    actions = [
      "secretsmanager:GetSecretValue","secretsmanager:PutSecretValue",
      "secretsmanager:DescribeSecret","secretsmanager:UpdateSecretVersionStage"
    ]
    resources = [
      aws_secretsmanager_secret.app_user.arn, "${aws_secretsmanager_secret.app_user.arn}:*",
      aws_secretsmanager_secret.connection_blob.arn, "${aws_secretsmanager_secret.connection_blob.arn}:*"
    ]
  }

  # S3 permissions – write-only access to audit bucket objects
  statement {
    actions   = ["s3:PutObject","s3:AbortMultipartUpload"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
  }

  # CloudWatch Logs permissions – unrestricted resource scope (service requirement)
  statement {
    actions   = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
    resources = ["*"]
  }
}

# Bind the inline policy to the Lambda role
resource "aws_iam_role_policy" "lambda" {
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}
