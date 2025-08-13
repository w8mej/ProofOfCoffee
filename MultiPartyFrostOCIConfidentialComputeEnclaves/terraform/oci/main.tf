# -----------------------------------------------------------------------------
# File: terraform/oci/main.tf
# What it does:
#   Provisions four **OCI Confidential VMs** (CVMs) — Coordinator, CA, TLog, AuthN —
#   and bootstraps each with Docker + the signed containers from GHCR via cloud-init.
#
# Security & Ops notes:
#   - Set is_confidential_instance = true to enable AMD SEV/SEV-SNP memory protection.
#   - Put instances on a private subnet; expose only necessary ports via NSGs.
#   - Use short-lived OCI auth (workload identity) or store secrets in OCI Vault.
#   - The cloud-init pins image tags via workflow TAG; in prod, pin digests.
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.30.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

locals {
  # GHCR image coordinates (override with -var or TF_VAR_ env)
  registry  = var.registry
  repo      = var.image_repo
  tag       = var.image_tag

  tee_policy_hash = var.tee_policy_hash
}

# Security group and network variables are expected to be provided.
# One compute instance per service for clean trust domains.
module "svc" {
  source = "./service"
  for_each = {
    coordinator = { port = 50051, image = "${local.registry}/${local.repo}/mpc-coordinator:${local.tag}" }
    ca          = { port = 50052, image = "${local.registry}/${local.repo}/mpc-ca:${local.tag}" }
    tlog        = { port = 50053, image = "${local.registry}/${local.repo}/mpc-tlog:${local.tag}" }
    auth        = { port = 50054, image = "${local.registry}/${local.repo}/mpc-auth:${local.tag}" }
  }

  compartment_ocid = var.compartment_ocid
  subnet_ocid      = var.subnet_ocid
  display_name     = "mpc-${each.key}"
  shape            = var.shape
  image_ocid       = var.image_ocid

  tee_policy_hash  = local.tee_policy_hash
  container_image  = each.value.image
  service_port     = each.value.port
}

output "public_ips" {
  value = { for k, m in module.svc : k => m.public_ip }
}
