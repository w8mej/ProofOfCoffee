terraform {
  # Pin providers to predictable versions for reproducible builds.
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0" # Modern OCI APIs (Functions, KMS, etc.)
    }
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0" # Newer auth/PKI resources and data sources
    }
  }
}

# OCI provider: authenticates with a user keypair.
# ⚠️ For production, prefer instance principals / dynamic auth where possible.
provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

# Vault provider: used to manage PKI, auth backends, and issue short‑lived certs.
# ⚠️ Do not hardcode tokens; pass via environment/TF_VAR and keep TTLs short.
provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}
