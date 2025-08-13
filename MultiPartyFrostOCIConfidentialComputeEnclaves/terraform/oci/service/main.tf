# -----------------------------------------------------------------------------
# File: terraform/oci/service/main.tf
# What it does:
#   Reusable module to create a single OCI CVM and launch a container for a
#   service (Coordinator, CA, TLog, or Auth) with TEE_POLICY_HASH exported.
#
# Security & Ops notes:
#   - Confidential instances isolate memory; fetch attestation in the guest.
#   - Cloud-init installs Docker, logs in (if needed), pulls image, runs container.
#   - For private GHCR, use PAT or OIDC/Workload Identity federation.
# -----------------------------------------------------------------------------

variable "compartment_ocid" { type = string }
variable "subnet_ocid"      { type = string }
variable "display_name"     { type = string }
variable "shape"            { type = string }
variable "image_ocid"       { type = string }

variable "tee_policy_hash"  { type = string }
variable "container_image"  { type = string }
variable "service_port"     { type = number }

data "template_file" "cloud_init" {
  template = file("${path.module}/../templates/cloud_init.yaml")
  vars = {
    container_image = var.container_image
    service_port    = var.service_port
    tee_policy_hash = var.tee_policy_hash
  }
}

resource "oci_core_instance" "svc" {
  availability_domain = 1
  compartment_id      = var.compartment_ocid
  shape               = var.shape
  display_name        = var.display_name

  create_vnic_details {
    subnet_id = var.subnet_ocid
    assign_public_ip = true
  }

  source_details {
    source_type = "image"
    image_id    = var.image_ocid
  }

  # Enable Confidential VM (AMD SEV/SEV-SNP)
  is_confidential_instance = true

  metadata = {
    user_data = base64encode(data.template_file.cloud_init.rendered)
  }
}

output "public_ip" {
  value = oci_core_instance.svc.public_ip
}
