############################################
# Pull a Postgres image (demo use)
# - Provides a local DB target for Vault's
#   Database secrets engine exercises.
############################################
resource "docker_image" "postgres" {
  name = "postgres:15"
}

############################################
# Run the Postgres container (demo only)
# ⚠ Security: hardcoded password + exposed port
#   are fine for local demos, not production.
############################################
resource "docker_container" "postgres" {
  name  = "vault-db"
  image = docker_image.postgres.latest

  env = [
    "POSTGRES_PASSWORD=supersecret" # Demo-only secret; use Vault/KMS in prod
  ]

  # Map container port to host (localhost dev convenience)
  ports {
    internal = 5432
    external = 5432
  }
}
