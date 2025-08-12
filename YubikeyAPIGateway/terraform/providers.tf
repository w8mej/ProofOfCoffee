terraform {
  required_providers {
    vault  = { source = "hashicorp/vault", version = "~> 4.0" }  # Vault secrets mgmt
    random = { source = "hashicorp/random", version = "~> 3.0" } # Secure random key gen
    null   = { source = "hashicorp/null", version = "~> 3.0" }   # Local commands/hooks
  }
}

# 🔐 Vault provider — API endpoint + auth token
provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}
