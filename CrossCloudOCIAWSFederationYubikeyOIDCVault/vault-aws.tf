########################################
# vault-aws.tf
# --------------------------------------
# Configures Vault's AWS Secrets Engine to 
# dynamically generate temporary AWS credentials.
# This improves security by avoiding long-lived IAM
# keys in code or environment variables.
########################################

# Enable AWS secrets backend in Vault
resource "vault_aws_secret_backend" "aws" {
  path                      = "aws"
  default_lease_ttl_seconds = 3600  # 1h
  max_lease_ttl_seconds     = 86400 # 24h
}

resource "vault_aws_secret_backend_role" "terraform" {
  backend         = vault_aws_secret_backend.aws.path
  name            = "terraform"
  credential_type = "iam_user"

  # Provide inline IAM JSON as a string
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:*", "s3:*"] # example: very permissive; tighten in prod
        Resource = "*"
      }
    ]
  })

  ttl = "1h"
}
