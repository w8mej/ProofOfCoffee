##########################################
# vault.tf
# Purpose: Create a Vault and two secrets (credential + connection blob)
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Creates a DEFAULT Vault and seeds two Vault secrets:
#   1) app_user (username/password) — bootstrap placeholder, immediately rotated on first run
#   2) connection_blob (DSNs, wallet pointer, metadata) — updated atomically alongside credential
#
# Security & Ops notes (PoC):
# - Bootstrap content is placeholder only; never commit real secrets.
# - DEFAULT vault manages KMS internally. Production: use dedicated KMS keys, enable key rotation,
#   and restrict key users.
# - Consumers should read secrets from their *local cloud’s* store (OCI apps → Vault) for latency/HA.
#
# Tunables:
# - Change secret names via variables to match org standards.
# - Add replicas if you use Vault secret replication across regions (supported feature).
##########################################

resource "oci_kms_vault" "vault" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name}-vault"
  vault_type     = "DEFAULT" # Production: consider dedicated keys + rotation policy
}

resource "oci_vault_secret" "app_user" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.vault.id
  secret_name    = var.oci_secret_name

  # Bootstrap placeholder; first rotation will replace this value
  secret_content {
    content_type = "BASE64"
    content      = base64encode(jsonencode({ username = "app_user", password = "bootstrap-temporary" }))
  }
}

resource "oci_vault_secret" "connection_blob" {
  compartment_id = var.compartment_ocid
  vault_id       = oci_kms_vault.vault.id
  secret_name    = var.oci_conn_blob_secret_name

  # Holds DSNs and wallet pointer; password may be omitted (recommended) or marked <pw> for in-place swap
  secret_content {
    content_type = "BASE64"
    content = base64encode(jsonencode({
      rds = {
        engine = "postgres",
        host   = "example",
        port   = 5432,
        dbname = "appdb",
        dsn    = "postgresql://app_user:<pw>@example:5432/appdb" # <pw> gets replaced by rotator if you embed
      },
      oci = {
        dsn    = "myadb_high",       # TNS alias from wallet
        wallet = "PAR_URL_OR_MOUNT", # Prefer mounted wallet dir or short-lived PAR URL
        user   = "app_user"
      },
      rotated_at = "bootstrap"
    }))
  }
}
