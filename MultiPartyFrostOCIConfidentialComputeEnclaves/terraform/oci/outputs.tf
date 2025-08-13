# -----------------------------------------------------------------------------
# File: terraform/oci/outputs.tf
# What it does:
#   Exposes public IPs of the deployed services.
# -----------------------------------------------------------------------------
output "public_ips" {
  description = "Public IPs by service name"
  value       = module.svc.public_ips
}
