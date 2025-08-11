############################################
# Enable AppRole authentication at /approle
# - Machine‑friendly login method for CI/CD.
############################################
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

############################################
# AppRole: terraform
# - Short‑lived tokens for Terraform runs.
# - One‑time SecretID use to prevent reuse.
# - TTLs enforce just‑in‑time access.
############################################
resource "vault_approle_auth_backend_role" "tf_role" {
  backend   = vault_auth_backend.approle.path
  role_name = "terraform"

  token_ttl          = "30m" # default lifetime for issued client tokens
  token_max_ttl      = "60m" # absolute cap if renewed
  secret_id_num_uses = 1     # single‑use SecretID (thwarts replay)
}
