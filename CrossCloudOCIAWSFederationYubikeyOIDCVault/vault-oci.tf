########################################
# vault-oci.tf
# --------------------------------------
# Configures Vault to securely store and manage
# OCI (Oracle Cloud Infrastructure) credentials
# for Terraform provisioning.
########################################

# Store OCI tenancy configuration in Vault
resource "vault_generic_endpoint" "oci" {
  path = "oci/config"

  data_json = jsonencode({
    tenancy_ocid = var.tenancy_ocid
    region       = var.region
  })
}

# Create a Vault role for Terraform to request OCI tokens
resource "vault_generic_endpoint" "oci_role" {
  path = "oci/roles/terraform"

  data_json = jsonencode({
    policies = ["default"] # Attach default Vault policy
    ttl      = "1h"        # Token TTL: 1 hour
  })
}
