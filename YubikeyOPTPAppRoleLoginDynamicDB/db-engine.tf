############################################
# Enable Vault's Database secrets engine
# - Backend responsible for issuing
#   short‑lived DB users/passwords.
############################################
resource "vault_mount" "database" {
  path = "database"
  type = "database"
}

############################################
# Connection config to PostgreSQL
# - Ties Vault to an actual DB instance.
# - `allowed_roles` limits which roles can
#   issue credentials from this connection.
#
# ⚠ Demo-only: hardcoded password & sslmode=disable
#   Replace with secure secret sourcing + TLS in real use.
############################################
resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.database.path
  name          = "postgres-db"
  allowed_roles = ["postgres-role"]

  postgresql {
    # Example: Dockerized Postgres reachable at runtime
    connection_url = "postgresql://postgres:supersecret@${docker_container.postgres.ip_address}:5432/postgres?sslmode=disable"
  }
}

############################################
# Dynamic credential role for Postgres
# - Creation statements define how Vault
#   provisions ephemeral DB users.
# - TTLs keep creds short‑lived by design.
############################################
resource "vault_database_secret_backend_role" "postgres_role" {
  backend = vault_mount.database.path
  name    = "postgres-role"
  db_name = vault_database_secret_backend_connection.postgres.name

  # Templated fields ({{name}}, {{password}}, {{expiration}})
  # are populated by Vault when issuing creds.
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
  ]

  default_ttl = "10m" # typical session length
  max_ttl     = "30m" # absolute upper bound
}
