# 🌍 AWS Provider
# Configured to deploy in us-east-1; credentials are sourced securely
provider "aws" {
  region = "us-east-1"
}

# 🔐 Vault Provider
# Used for issuing short-lived SSH certificates & managing secrets
provider "vault" {
  address = "http://127.0.0.1:8200"
}
