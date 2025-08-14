###############################################################################
# Terraform — Outputs for FROST signer/keygen Public IPs
#
# Security & Ops
# - These outputs are **primarily for debugging/bootstrap**; in a private-only
#   deployment, both values should be `null`/empty.
# - If these ever return non-empty values, investigate why public IPs were
#   provisioned — could indicate a misconfiguration in subnet or instance
#   `assign_public_ip` setting.
# - Never depend on these for operational automation in a production **private**
#   deployment; use private IPs + VPN/Service Gateway for access.
#
# Usage
# - `terraform output frost_signer_public_ips` → list of signer public IPs
# - `terraform output frost_keygen_public_ip`  → keygen host public IP
#
# Compliance / Audit
# - For hardened environments, integrate a CI/CD check that fails if these
#   outputs are non-empty.
###############################################################################

output "frost_signer_public_ips" {
  description = "Public IPs of the FROST signers (should be empty if private-only deployment)"
  value       = [for i in oci_core_instance.frost_signer : i.public_ip]
}

output "frost_keygen_public_ip" {
  description = "Public IP of keygen host (should be empty if private-only deployment)"
  value       = oci_core_instance.frost_keygen.public_ip
}
