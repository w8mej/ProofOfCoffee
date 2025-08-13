##########################################
# iam.tf
# Purpose: Grant the Function least-privilege access to Vault and Object Storage
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Creates a Dynamic Group that matches Functions in the compartment.
# - Attaches a Policy allowing that Dynamic Group to:
#   * use secret-family (read/update secret versions) in the compartment
#   * manage objects in the specific audit bucket (write audit logs)
#   * use object-family for Object Storage interactions (narrowed by bucket name)
#
# Security & Ops notes (PoC):
# - The matching rule scopes to fnfunc resources in the given compartment.
# - Policy includes "manage objects" limited by target.bucket.name to minimize blast radius.
# - Consider splitting policies for read vs write and scoping namespace/bucket more tightly.
#
# Tunables:
# - Change matching_rule if you want to scope to a specific function OCID instead of the whole compartment.
# - Update the bucket name predicate if you rename the audit bucket.
##########################################

resource "oci_identity_dynamic_group" "fn_group" {
  compartment_id = var.compartment_ocid
  name           = "${var.name}-fn-dg"
  description    = "Functions in compartment can access Vault and Object Storage"

  # Matches all Function resources in this compartment
  matching_rule = "ALL {resource.type = 'fnfunc', resource.compartment.id = '${var.compartment_ocid}'}"
}

resource "oci_identity_policy" "fn_policy" {
  compartment_id = var.compartment_ocid
  name           = "${var.name}-fn-policy"
  description    = "Allow functions to read/update secrets and write audit logs"

  statements = [
    # Vault secrets: read/update versions (secret-family) within this compartment
    "Allow dynamic-group ${oci_identity_dynamic_group.fn_group.name} to use secret-family in compartment id ${var.compartment_ocid}",

    # Object Storage: manage objects in the specific audit bucket only
    "Allow dynamic-group ${oci_identity_dynamic_group.fn_group.name} to manage objects in compartment id ${var.compartment_ocid} where target.bucket.name='${var.name}-rotation-audit'",

    # Object Storage: general usage (list/get metadata); still compartment-scoped
    "Allow dynamic-group ${oci_identity_dynamic_group.fn_group.name} to use object-family in compartment id ${var.compartment_ocid}"
  ]
}
