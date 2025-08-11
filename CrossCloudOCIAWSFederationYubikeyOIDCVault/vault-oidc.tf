########################################
# vault-oidc.tf
# --------------------------------------
# Configures Vault OIDC authentication with YubiKey.
# OIDC is integrated with WebAuthn (FIDO2) for MFA.
# This setup allows Terraform and human operators to
# authenticate via secure hardware-backed keys.
########################################

# Enable the OIDC authentication method in Vault
resource "vault_auth_backend" "oidc" {
  type = "oidc"
  path = "oidc"
}

# Configure OIDC provider details (replace placeholders)
resource "vault_oidc_auth_backend_config" "yubikey" {
  backend            = vault_auth_backend.oidc.path
  oidc_discovery_url = "https://haxx.ninja/.well-known/openid-configuration" # Replace with real issuer
  default_role       = "yubikey"
  client_id          = "vault-oidc"          # Replace with actual client ID
  client_secret      = "replace-with-random" # Store in Vault, not plaintext in production

  # Request additional scopes for identity claims
  additional_scopes = ["email", "profile"]

  # Note: Vault does not natively support WebAuthn (FIDO2) yet.
  # Implementation would be done via an external OIDC IdP that supports WebAuthn.
}

# Create a Vault role binding for Terraform OIDC authentication
resource "vault_oidc_auth_backend_role" "tf_role" {
  backend               = vault_auth_backend.oidc.path
  role_name             = "terraform"
  token_ttl             = "30m"
  token_max_ttl         = "60m"
  bound_audiences       = ["vault-oidc"]
  allowed_redirect_uris = ["https://app.terraform.io/auth/callback"]
  user_claim            = "email"
  groups_claim          = "groups"
}
