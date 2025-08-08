############################################
# Vault Policy: AWS Dynamic Credentials
# -----------------------------------------
# Grants read access to the dynamic AWS
# credentials endpoint for the Vault role
# `terraform-role`.
#
# This policy is intended for workloads that
# require short-lived AWS credentials to
# perform infrastructure provisioning via
# Terraform.
#
# Security benefits:
# - No persistent AWS credentials stored in code
# - Credentials automatically expire per Vault lease TTL
############################################

path "aws/creds/terraform-role" {
  # Allowed capabilities for this path:
  # - read: Retrieve the generated AWS credentials
  capabilities = ["read"]
}
