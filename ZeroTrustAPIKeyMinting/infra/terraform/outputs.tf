###############################################################################
# Terraform Output — KMS Key OCID
#
# Security & Ops
# - This output reveals the **OCID** of the HSM-protected approval key used
#   for MPC minting quorum receipts.
# - The key is created in an OCI KMS Vault with **protection_mode = "HSM"** and
#   algorithm `RSA-2048` for signing.
# - The OCID can be used by trusted workloads (as allowed by IAM policies) to
#   reference the key when invoking KMS `Sign` operations.
#
# Hardening Notes
# - Avoid exposing this output publicly or committing to version control.
# - Consider using `sensitive = true` if you do not want the OCID to appear in
#   CLI output or logs.
###############################################################################

output "kms_key_ocid" {
  value       = oci_kms_key.sign_key.id
  description = "OCID of the HSM approval key"
  # sensitive = true  # Uncomment to hide from Terraform plan/apply output
}
