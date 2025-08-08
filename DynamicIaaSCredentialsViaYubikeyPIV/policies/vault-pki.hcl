###############################################
# 🔐 PKI Secrets Engine Access
# Grants full access to any path beginning with `pki`
# Typically used for managing Root or Intermediate CAs,
# issuing and revoking certs, or configuring roles.
###############################################
path "pki*" {
  capabilities = [
    "create", # Allow creation of new certs, roles, or configurations
    "read",   # Read certificate or configuration data
    "update", # Modify PKI configuration or reissue certificates
    "list",   # List roles, certs, or backend details
    "delete"  # Revoke certs or delete roles/configs
  ]
}

###############################################
# ✅ Certificate-Based Authentication Configuration
# Grants access to manage Vault's `cert` auth method.
# This includes uploading client CA certs and mapping certs to Vault identities.
###############################################
path "auth/cert/*" {
  capabilities = [
    "create", # Upload new client certificates
    "read",   # View current certificate mappings or configuration
    "update", # Modify certificate-based authentication settings
    "list"    # Enumerate cert mappings or settings
  ]
}
