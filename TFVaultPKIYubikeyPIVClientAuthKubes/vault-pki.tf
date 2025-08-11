# -------------------------------------------------------------------
# File: vault-pki.tf
# -------------------------------------------------------------------
# Purpose:
#   Configures Vault to act as both a Root and Intermediate Certificate
#   Authority (CA) for Kubernetes client certificates. This includes:
#     - Mounting PKI engines
#     - Generating a self-signed root CA
#     - Creating and signing an intermediate CA
#
# Flow:
#   1. Mount Root CA (`pki-root`)
#   2. Mount Intermediate CA (`pki-int`)
#   3. Generate Root CA certificate
#   4. Generate Intermediate CSR
#   5. Sign Intermediate CSR with Root CA
#   6. Import signed Intermediate certificate into Vault
#
# Security Notes:
#   - Root CA has a long validity (1 year), stored securely in Vault.
#   - Intermediate CA has shorter validity (30 days) to reduce risk.
# -------------------------------------------------------------------

# Root CA mount
resource "vault_mount" "pki_root" {
  path                  = "pki-root"
  type                  = "pki"
  description           = "Root CA for the cluster"
  max_lease_ttl_seconds = 31536000 # 1 year
}

# Intermediate CA mount
resource "vault_mount" "pki_int" {
  path                  = "pki-int"
  type                  = "pki"
  description           = "Intermediate CA for client certs"
  max_lease_ttl_seconds = 2592000 # 30 days
}

# Generate the Root CA certificate
resource "vault_generic_endpoint" "root_ca" {
  path = "pki-root/root/generate/internal"
  data_json = jsonencode({
    common_name = "haxx.ninja Root CA"
    ttl         = "8760h" # 1 year
  })
}

# Generate Intermediate CA CSR
resource "vault_generic_endpoint" "int_csr" {
  path = "pki-int/intermediate/generate/internal"
  data_json = jsonencode({
    common_name = "haxx.ninja Intermediate"
    ttl         = "4380h" # 6 months
  })
}

# Sign Intermediate CSR with Root CA
resource "vault_generic_endpoint" "int_sign" {
  path = "pki-root/root/sign-intermediate"
  data_json = jsonencode({
    csr = vault_generic_endpoint.int_csr.data["csr"]
    ttl = "4380h" # 6 months
  })
}

# Upload signed Intermediate certificate into Vault
resource "vault_generic_endpoint" "int_set_signed" {
  path = "pki-int/intermediate/set-signed"
  data_json = jsonencode({
    certificate = vault_generic_endpoint.int_sign.data["certificate"]
  })
}
