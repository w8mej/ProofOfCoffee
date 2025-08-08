############################################
# terraform.tfvars (Infrastructure Setup)
# -----------------------------------------
# This configuration demonstrates using HashiCorp Vault
# with a YubiKey client certificate to securely retrieve
# temporary AWS credentials, and then provisioning a 
# harmless example AWS S3 bucket using those credentials.
#
# Security benefits:
# - No hardcoded AWS credentials
# - All AWS access is short-lived via Vault dynamic secrets
# - TLS client authentication using a YubiKey
############################################

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0" # Latest major Vault provider
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # Latest major AWS provider
    }
  }
}

############################################
# Vault Provider Configuration
############################################
provider "vault" {
  address = "http://127.0.0.1:8200" # Vault API endpoint

  # TLS client authentication using certificates stored on a YubiKey
  client_cert = file("yubikey_cert.pem")
  client_key  = file("yubikey_key.pem") # Exported with:
  # yubico-piv-tool -a read-object -s 9c -r 0x10
}

############################################
# Pull Temporary AWS Credentials from Vault
############################################
data "vault_aws_access_credentials" "temp" {
  backend = "aws"            # Path to Vault's AWS secrets engine
  role    = "terraform-role" # Vault role granting AWS permissions
}

############################################
# AWS Provider Configuration
############################################
provider "aws" {
  access_key = data.vault_aws_access_credentials.temp.access_key
  secret_key = data.vault_aws_access_credentials.temp.secret_key
  token      = data.vault_aws_access_credentials.temp.security_token
  region     = "us-east-1" # Example region
}

############################################
# Example AWS Resource
############################################
resource "aws_s3_bucket" "demo" {
  bucket = "vault-yubikey-demo-${random_id.suffix.hex}" # Globally unique bucket name
  acl    = "private"                                    # No public access
}

############################################
# Random Suffix Generator
# ------------------------------------------
# Ensures bucket names remain unique across
# AWS global namespace.
############################################
resource "random_id" "suffix" {
  byte_length = 4
}
