##########################################
# outputs.tf
# Purpose: Export key resource IDs for wiring into apps/other stacks
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
# -----------------------------------------------------------------------------
# What it does
# -----------------------------------------------------------------------------
# - Exposes key resource IDs (e.g., secret IDs, ARN, or Vault paths) that
#   other Terraform stacks, CI/CD jobs, or monitoring dashboards can consume.
# - Acts as an integration point so dependent systems can easily hook into
#   the deployed resources without manual lookups.
#
# -----------------------------------------------------------------------------
# Ops notes
# -----------------------------------------------------------------------------
# - After running `terraform apply` in CI, emit these outputs in job logs so
#   application teams can self-service by retrieving the necessary IDs for
#   secret lookups or dashboard configurations.
# - Keep outputs restricted to non-sensitive identifiers — do not expose
#   credentials, API keys, or private data in Terraform outputs.


output "aws_secret_id" { value = aws_secretsmanager_secret.app_user.id }
output "aws_conn_blob_secret_id" { value = aws_secretsmanager_secret.connection_blob.id }
output "audit_bucket" { value = aws_s3_bucket.audit.bucket }
output "lambda_arn" { value = aws_lambda_function.rotate.arn }
