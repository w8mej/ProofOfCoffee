##########################################
# outputs.tf
# Purpose: Expose key OCIDs/names for wiring and observability
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Exposes secret OCIDs, audit bucket name, and function OCID for downstream stacks and dashboards.
#
# Security & Ops notes (PoC):
# - Avoid printing secret *values*; only metadata/identifiers are output.
#
# Tunables:
# - Add outputs for function endpoint/log group names if you standardize on monitoring.
##########################################

output "oci_secret_ocid" { value = oci_vault_secret.app_user.id }
output "oci_conn_blob_secret_ocid" { value = oci_vault_secret.connection_blob.id }
output "oci_audit_bucket" { value = oci_objectstorage_bucket.audit.name }
output "oci_function_ocid" { value = oci_functions_function.rotate.id }
