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
  default_lease_ttl_seconds = 3600  # Default TTL: 1 hour
  max_lease_ttl_seconds     = 86400 # Max TTL: 24 hours
}

# Define a Vault role for Terraform to obtain AWS credentials
resource "vault_aws_secret_backend_role" "terraform" {
  backend         = vault_aws_secret_backend.aws.path
  name            = "terraform"
  credential_type = "iam_user"

  # IAM policy assigned to dynamic credentials
  policy = {
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : ["ec2:*", "s3:*"], # Example: full EC2 and S3 access
        "Resource" : "*"
      }
    ]
  }

  ttl = "1h" # Lease duration for the generated credentials
}
