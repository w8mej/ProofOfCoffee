##########################################
# lambda.tf
# Purpose: Rotation Lambda (container image) + DLQ + async policy + alarm
# Status: PROOF OF CONCEPT — NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What this does
# -----------------------------------------------------------------------------
# - Deploys the rotation Lambda from an immutable container image (ECR).
# - Configures environment needed to rotate creds across AWS RDS + OCI ADB-D.
# - Adds an SQS Dead Letter Queue (DLQ) and points the Lambda to it.
# - Controls async retries and event max age; routes final failures to DLQ.
# - Creates a CloudWatch alarm on DLQ backlog for operational visibility.
#
# -----------------------------------------------------------------------------
# Security & Ops notes (PoC)
# -----------------------------------------------------------------------------
# - DLQ uses SSE-SQS (AWS-managed KMS) for simplicity. For stricter control,
#   switch to a CMK and lock key policy to principals that need decrypt.
# - Queue policy only allows *this* Lambda function (by ARN) to SendMessage.
# - Concurrency is capped at 1 to serialize rotations (avoid race conditions).
# - No VPC config here. If RDS is private, add vpc_config + ENI permissions.
# - AUDIT_HASH_SALT_SSM should be sourced from SSM/Secrets Manager in prod.
#
# -----------------------------------------------------------------------------
# Tunables
# -----------------------------------------------------------------------------
# - timeout / memory_size: adjust for TCPS wallet handshake and cross-cloud RTT.
# - maximum_retry_attempts / maximum_event_age_in_seconds: tune for your SLOs.
# - DLQ retention (14 days here) and alarm thresholds can be changed below.
##########################################

# ----------------------------- Lambda function -------------------------------

resource "aws_lambda_function" "rotate" {
  function_name                  = "${var.name}-rotate-credential"
  package_type                   = "Image"           # Container image, not ZIP
  image_uri                      = var.ecr_image_uri # Set by CI to an immutable tag/digest
  role                           = aws_iam_role.lambda.arn
  timeout                        = 120 # seconds
  memory_size                    = var.lambda_memory_mb
  reserved_concurrent_executions = 1 # Serialize to avoid overlapping rotations

  # Dead Letter Queue for async failures
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

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

      # Rotation frequency (metadata; actual cadence is EventBridge)
      ROTATION_MINUTES = "20"
    }
  }
}

# Optional: manage log retention explicitly (helps keep logs tidy in PoC)
resource "aws_cloudwatch_log_group" "rotate" {
  name              = "/aws/lambda/${aws_lambda_function.rotate.function_name}"
  retention_in_days = 30
}

# --------------------------- Async invoke policy -----------------------------

resource "aws_lambda_event_invoke_config" "rotate_async" {
  function_name = aws_lambda_function.rotate.function_name

  # Tunables: retry & max age for async events
  maximum_retry_attempts       = 2    # Keep small to avoid thundering herd
  maximum_event_age_in_seconds = 3600 # 1 hour TTL for the event

  destination_config {
    on_failure {
      destination = aws_sqs_queue.lambda_dlq.arn
    }
  }
}

# ---------------------------------- DLQ --------------------------------------

resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "${var.name}-lambda-dlq"
  message_retention_seconds  = 1209600         # 14 days (max) for forensics/replay
  kms_master_key_id          = "alias/aws/sqs" # SSE-SQS (AWS-managed KMS)
  visibility_timeout_seconds = 30
}

# Allow *only this* Lambda function to send messages to the DLQ
data "aws_iam_policy_document" "sqs_dlq_policy" {
  statement {
    sid       = "AllowLambdaToSendToDLQ"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.lambda_dlq.arn]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_lambda_function.rotate.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "lambda_dlq" {
  queue_url = aws_sqs_queue.lambda_dlq.id
  policy    = data.aws_iam_policy_document.sqs_dlq_policy.json
}

# ------------------------------ DLQ Alarm ------------------------------------

# Basic alarm when there are any visible messages in the DLQ (threshold=1).
# Production: route to SNS/PagerDuty via alarm_actions and set sensible thresholds.
resource "aws_cloudwatch_metric_alarm" "dlq_backlog" {
  alarm_name          = "${var.name}-lambda-dlq-backlog"
  alarm_description   = "Messages visible in ${aws_sqs_queue.lambda_dlq.name} (rotation failures)."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.lambda_dlq.name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  # Optional: wire SNS topics here (leave empty in PoC)
  alarm_actions = []
  ok_actions    = []
}
