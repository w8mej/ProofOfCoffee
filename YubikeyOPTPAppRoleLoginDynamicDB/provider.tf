############################################
# Vault provider with AppRole login
# - Terraform authenticates to Vault using
#   role_id + secret_id obtained via unwrap.
# - Keeps runs non-interactive and scoped by policy.
############################################
provider "vault" {
  address = "http://127.0.0.1:8200"

  auth_login {
    path = "auth/approle/login"
    parameters = {
      role_id   = vault_approle_auth_backend_role_id.terraform_role.role_id
      secret_id = vault_generic_secret.secret_id.data["secret_id"] # from unwrap
    }
  }
}
