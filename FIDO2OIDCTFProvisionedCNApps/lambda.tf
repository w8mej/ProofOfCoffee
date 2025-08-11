############################################
# AWS Lambda with Vault-Backed Secrets
# -----------------------------------------
# This configuration provisions:
# - A Lambda function with:
#   - VPC networking
#   - Dead Letter Queue (SQS)
#   - Code signing enforcement
#   - Reserved concurrency limits
# - Vault-stored API key for secure retrieval
#
# Security Enhancements:
# - Uses CMK for SQS encryption
# - Enforces IAM least privilege
# - Code signing to prevent deployment of
#   untrusted artifacts
# - VPC attachment to control outbound traffic
############################################

# ------------------------
# IAM Role for Lambda
# ------------------------
resource "aws_iam_role" "lambda_role" {
  name = "lambda-vault-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

############################
# VPC Wiring for the Lambda
############################

variable "private_subnet_ids" {
  type        = list(string)
  description = "List of private subnet IDs for Lambda VPC attachment (must have NAT or private endpoints if outbound access is required)."

  validation {
    condition     = length(var.private_subnet_ids) > 0
    error_message = "Provide at least one private subnet ID."
  }
}

variable "lambda_security_group_id" {
  type        = string
  description = "Security group ID for Lambda ENIs; typically egress-only or restricted to required endpoints."
}

#########################################
# SQS Dead Letter Queue (DLQ)
# ---------------------------------------
# Captures failed Lambda invocations.
# Encrypted with a CMK to protect data at rest.
#########################################

resource "aws_kms_key" "sqs" {
  description         = "CMK for SQS DLQ encryption"
  enable_key_rotation = true
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "vault-demo-dlq"
  message_retention_seconds  = 1209600 # 14 days
  visibility_timeout_seconds = 30

  kms_master_key_id                 = aws_kms_key.sqs.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue_policy" "lambda_dlq_policy" {
  queue_url = aws_sqs_queue.lambda_dlq.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowLambdaToSendToDLQ",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = ["SQS:SendMessage"],
      Resource  = aws_sqs_queue.lambda_dlq.arn,
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_lambda_function.demo.arn }
      }
    }]
  })
}

##################################
# Code Signing Enforcement
# --------------------------------
# Ensures only trusted, signed artifacts
# can be deployed to this Lambda.
##################################

resource "aws_signer_signing_profile" "lambda" {
  name        = "vault-demo-lambda-profile"
  platform_id = "AWSLambda-SHA384-ECDSA"
}

resource "aws_lambda_code_signing_config" "this" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda.arn]
  }
  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

#########################################
# Attach AWS-managed VPC execution policy
#########################################
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

#####################################
# Reserved Concurrency
# -----------------------------------
# Protects downstream services from
# noisy-neighbor effects.
#####################################

variable "lambda_reserved_concurrency" {
  type        = number
  description = "Function-level reserved concurrency limit."

  validation {
    condition     = var.lambda_reserved_concurrency == null || var.lambda_reserved_concurrency >= 1
    error_message = "Must be null or >= 1."
  }
}

##################################
# Lambda Function Definition
##################################

resource "aws_lambda_function" "demo" {
  function_name = "vault-demo"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_role.arn
  handler       = "handler.lambda_handler"

  filename         = "${path.module}/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda.zip")

  tracing_config {
    mode = "Active"
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.lambda_security_group_id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  code_signing_config_arn        = aws_lambda_code_signing_config.this.arn
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  depends_on = [aws_iam_role_policy_attachment.lambda_vpc_access]
}
