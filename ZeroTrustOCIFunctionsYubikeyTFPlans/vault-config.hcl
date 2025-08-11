############################################
# PKI mount used to issue short‑lived certs
# bound to Terraform plan fingerprints.
# - Separate PKI mount keeps scope tight.
# - Max lease set to 24h for safety.
############################################
resource "vault_mount" "yubisign_ca" {
  path                  = "yubisign"
  type                  = "pki"
  description           = "CA for verifying Terraform plan signatures"
  max_lease_ttl_seconds = 86400 # 24h
}

############################################
# Internal Root CA for YubiSign
# - Self‑signed root for the PoC.
# - 1‑year TTL; in production use an
#   intermediate CA and protect the root.
############################################
resource "vault_pki_secret_backend_root_cert" "yubisign_root" {
  backend     = vault_mount.yubisign_ca.path
  type        = "internal" # Self‑managed CA inside Vault
  common_name = "yubisign.local"
  ttl         = "8760h" # ~1 year
}
