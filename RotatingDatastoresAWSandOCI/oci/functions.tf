##########################################
# functions.tf
# Purpose: Deploy the rotation worker as an OCI Function (container image)
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Creates a Functions Application (namespacing + networking via subnet).
# - Deploys the rotation Function from an OCIR image and configures env vars.
#
# Security & Ops notes (PoC):
# - Uses a private subnet ID; ensure NAT/egress is available for outbound to ADB/RDS/Secrets.
# - No concurrency guard here; avoid overlapping rotations by scheduling or adding internal lock.
# - Secrets/IDs are passed as env vars. Production: consider using OCI Vault bindings or
#   short-lived tokens/refs where possible.
#
# Tunables:
# - memory_in_mbs / timeout_in_seconds: raise for wallet TCPS handshake or cross-cloud latency.
# - ocir_image_uri: point to immutable digest/tag from CI.
# - Subnet: change to a subnet with required egress and security lists/NSGs.
##########################################

resource "oci_functions_application" "app" {
  compartment_id = var.compartment_ocid
  display_name   = "${var.name}-rotation-app"
  subnet_ids     = [var.subnet_ocid] # Private subnet preferred; ensure outbound egress
}

resource "oci_functions_function" "rotate" {
  application_id     = oci_functions_application.app.id
  display_name       = "${var.name}-rotate-credential"
  image              = var.ocir_image_uri # e.g., phx.ocir.io/tenancyns/rotator:<gitsha>
  memory_in_mbs      = 512                # Tunable: CPU/mem sizing affects cold starts
  timeout_in_seconds = 120                # Tunable: allow for DB connects + ALTER USER

  # Environment configuration consumed by the worker
  config = {
    TARGETS                   = "rds,oci"                           # Rotate on both sides
    AWS_SECRET_ID             = var.aws_secret_id                   # SM secret ARN (credentials)
    AWS_CONN_BLOB_SECRET_ID   = var.aws_conn_blob_secret_id         # SM secret ARN (connection blob)
    OCI_SECRET_OCID           = oci_vault_secret.app_user.id        # Vault secret OCID (credentials)
    OCI_CONN_BLOB_SECRET_OCID = oci_vault_secret.connection_blob.id # Vault secret OCID (connection blob)
    LOG_BUCKET                = oci_objectstorage_bucket.audit.name # Write-only audit logs
    OCI_OS_NAMESPACE          = var.os_namespace                    # Needed for Object Storage client
    ROTATION_MINUTES          = "20"                                # Keep in sync with Events schedule

    # ADB-D specifics (set per env, not committed):
    # OCI_ADB_USER=app_user
    # OCI_ADB_DSN=myadb_high (TNS alias) or EZCONNECT
    # OCI_ADB_WALLET_MOUNT=/opt/adb_wallet  (preferred; mounted secret)
    # OCI_ADB_WALLET_URL=https://... (short-lived PAR)  OR  OCI_ADB_WALLET_B64=<base64>
  }
}
