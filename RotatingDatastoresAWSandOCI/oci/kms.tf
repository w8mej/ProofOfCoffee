##########################################
# kms.tf
# Purpose: (Optional) Note about dedicated KMS keys for Vault secrets
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Documents that the DEFAULT vault manages keys internally.
#
# Security & Ops notes (PoC):
# - Production: create an OCI KMS key and associate Vault secrets with it for stricter key control,
#   rotation, and audit. Limit key user principals to the Function dynamic group only if feasible.
#
# Tunables:
# - Add `oci_kms_key` resources and link via Vault/Secret fields when moving to production.
##########################################

# Optional: dedicated KMS key for Vault secrets can be added.
# Using DEFAULT vault which manages keys internally. Add oci_kms_key if needed.
