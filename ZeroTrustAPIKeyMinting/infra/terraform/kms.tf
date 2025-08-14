###############################################################################
# Terraform — OCI KMS Vault + Signing Key for MPC Minting
#
# Security & Ops
# - Creates a dedicated **Vault** in OCI KMS to store cryptographic material.
# - Creates an **HSM-protected RSA-2048 signing key** (`SIGN` operation only).
#   • Protection mode: HSM → ensures private key never leaves Oracle-managed
#     hardware security modules.
# - Restricts usage via **dynamic group + IAM policy** so only instances in
#   this compartment can use the key to approve minting operations.
# - Policies allow:
#     1. `use keys` (required to sign data)
#     2. `use vaults` (required to access the vault itself)
# - Designed for mTLS + JWT signature co-signing for zero-trust mint receipts.
#
# Tunables / Config
# - `vault_type`: DEFAULT → change to `VIRTUAL_PRIVATE` for private endpoint.
# - `key_shape`: adjust `algorithm` or `length` if compliance requires (e.g.,
#   RSA-3072, ECDSA-P384).
# - `matching_rule`: modify to narrow eligible compute shapes, tags, or ADs.
# - `protection_mode`: HSM → keep; only downgrade to `SOFTWARE` for testing.
#
# Potential Improvements
# - Rotate keys regularly via `oci_kms_key_version` resources + schedule.
# - Use separate KMS keys for different signing roles (mint approval vs. audit).
# - Bind policy to **instance principals with specific tags** instead of all
#   instances in the compartment for finer-grained control.
# - Enable **Vault Replication** if cross-region failover is a requirement.
#
# Production Hardening Ideas
# - Enforce Vault private endpoints and route via Service Gateway.
# - Use OCI KMS's audit log integration to record every signing operation.
# - Integrate with OPA/Envoy to verify that every mint request’s JWT receipt
#   has been signed by this KMS key.
###############################################################################

resource "oci_kms_vault" "vault" {
  compartment_id = var.compartment_ocid
  display_name   = "mpc-minting-vault"
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "sign_key" {
  compartment_id      = var.compartment_ocid
  display_name        = "mpc-minting-approval-key"
  management_endpoint = oci_kms_vault.vault.management_endpoint
  key_shape {
    algorithm = "RSA"
    length    = 2048
  }
  protection_mode = "HSM"
  key_operation   = "SIGN"
}

# Dynamic group for instances in the compartment
resource "oci_identity_dynamic_group" "dg_mpc" {
  compartment_id = var.tenancy_ocid
  name           = "dg-mpc-minting"
  description    = "Instances that can use KMS for mint approvals"
  matching_rule  = "ALL {instance.compartment.id = '${var.compartment_ocid}'}"
}

# Policy to allow dynamic group to use the key for signing
resource "oci_identity_policy" "policy_kms" {
  compartment_id = var.tenancy_ocid
  name           = "mpc-minting-kms-policy"
  description    = "Allow instances to use KMS key for signing"
  statements = [
    "Allow dynamic-group ${oci_identity_dynamic_group.dg_mpc.name} to use keys in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group ${oci_identity_dynamic_group.dg_mpc.name} to use vaults in compartment id ${var.compartment_ocid}"
  ]
}

output "kms_key_ocid" {
  description = "OCID of the KMS key used to co-sign JWT receipts"
  value       = oci_kms_key.sign_key.id
}
