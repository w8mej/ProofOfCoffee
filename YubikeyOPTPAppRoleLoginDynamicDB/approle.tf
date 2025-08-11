############################################
# Vault Policy: read-only dynamic DB creds
# - Grants permission to fetch short‑lived
#   PostgreSQL credentials from Vault.
############################################
resource "vault_policy" "db_access" {
  name = "db-access"

  # Principle of least privilege: read only the creds endpoint
  policy = <<EOT
path "database/creds/postgres-role" {
  capabilities = ["read"]
}
EOT
}

############################################
# Vault AppRole: machine auth for Terraform
# - Terraform authenticates via AppRole and
#   receives a token scoped to db-access policy.
# - Short TTLs enforce just‑in‑time access.
############################################
resource "vault_approle_auth_backend_role" "terraform_role" {
  role_name      = "terraform-db"
  token_policies = [vault_policy.db_access.name]
  token_ttl      = "30m" # default lifetime
  token_max_ttl  = "1h"  # hard cap
}
