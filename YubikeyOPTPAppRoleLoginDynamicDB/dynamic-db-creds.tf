############################################
# Fetch short‑lived DB credentials from Vault
# - Reading this path causes Vault to
#   generate a fresh username/password.
############################################
data "vault_generic_endpoint" "db_creds" {
  path = "database/creds/postgres-role"
}

############################################
# Outputs (demo visibility)
# ⚠ In real systems, do NOT print secrets.
#   Pass them directly to apps or inject as
#   environment variables/connection strings.
############################################
output "db_username" {
  value       = data.vault_generic_endpoint.db_creds.data["username"]
  description = "Ephemeral DB username issued by Vault (demo only—do not output in prod)."
}

output "db_password" {
  value       = data.vault_generic_endpoint.db_creds.data["password"]
  sensitive   = true
  description = "Ephemeral DB password issued by Vault (demo only—do not output in prod)."
}
