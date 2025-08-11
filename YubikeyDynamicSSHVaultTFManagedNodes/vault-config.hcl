# -------------------------------------------------------------------
# Vault Listener Configuration
# -------------------------------------------------------------------
# Purpose:
#   Configure Vault to run locally on 127.0.0.1:8200 without TLS 
#   (for development/testing ONLY) and enable the Vault web UI.
#
# Security Warning:
#   - `tls_disable = true` is *never* recommended in production.
#   - For production, configure TLS with a valid certificate.
# -------------------------------------------------------------------
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

ui = true
