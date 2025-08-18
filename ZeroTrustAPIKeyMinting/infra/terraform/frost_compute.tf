###############################################################################
# Terraform — OCI Object Storage + CVMs for FROST Keygen & Signers (documented)
#
# Security & Ops
# - Object Storage bucket uses Standard tier, versioning enabled (CKV_OCI_8), 
#   object events enabled (CKV_OCI_7), and encrypted with KMS key (CKV_OCI_9).
# - All compute instances are private (assign_public_ip = false).
# - Confidential VM hardening: Secure Boot, TPM, Measured Boot, Memory Encryption all enabled.
# - PV encryption-in-transit enabled (CKV_OCI_4) and IMDS v1 disabled (CKV_OCI_5).
# - Place instances in different subnets / ADs for signer fault domain isolation.
# - Network security groups (NSGs) should be applied to limit ingress/egress 
#   only to Coordinator ↔ Signer and Object Storage endpoints.
#
# Tunables / Config
# - `var.ocpus`, `var.memory_gbs`: Adjust compute sizing per role.
# - `var.image_ocid`: Use OCI Confidential Compute-capable images.
# - `var.ssh_public_key`: For operational access (break-glass).
# - `var.kms_key_ocid`: KMS key for Object Storage encryption at rest.
# - `local.frost_keygen_cloud_init` / `local.frost_signer_cloud_init`: Bootstrap logic for each role.
# - Subnet configuration: `oci_core_subnet.frost_subnet[]` determines AD/FD placement.
#
# Improvements / Production
# - Add **NetworkPolicies** at the Kubernetes level (if migrated to OKE) or NSGs here to 
#   enforce explicit service-to-service allowlists.
# - Replace `git clone` / local build in cloud-init with a **pinned digest** from a private registry.
# - Integrate with OCI Logging / Monitoring for metrics, logs, and alerts on signer/keygen health.
# - Attach instance principals with fine-grained IAM policies for Object Storage/KMS, avoid static keys.
# - Create object lifecycle policies in Object Storage for old share files if rotation is frequent.
#
# Production Readiness
# - Ensure all signer instances are deployed in **separate fault domains** and subnets.
# - Consider autoscaling or self-healing orchestration (OKE DaemonSets / StatefulSets).
# - Rotate TLS/mTLS certs automatically via cert-manager or OCI Certificates service.
# - Implement attestation verification at startup to ensure only approved AMIs/configurations run.
###############################################################################

data "oci_objectstorage_namespace" "ns" {}

resource "oci_objectstorage_bucket" "frost_bucket" {
  compartment_id        = var.compartment_ocid
  name                  = "frost-shares-${var.display_name}"
  namespace             = data.oci_objectstorage_namespace.ns.namespace
  storage_tier          = "Standard"
  versioning            = "Enabled"        # CKV_OCI_8: Versioning required for rollback/recovery
  object_events_enabled = true             # CKV_OCI_7: Enable events for bucket activity
  kms_key_id            = var.kms_key_ocid # CKV_OCI_9: KMS encryption for compliance
}

resource "oci_core_instance" "frost_keygen" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = "frost-keygen"
  shape               = var.instance_shape

  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memory_gbs
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.frost_subnet[0].id
    assign_public_ip = false
    hostname_label   = "frostkeygen"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = base64encode(local.frost_keygen_cloud_init)
  }

  launch_options {
    is_pv_encryption_in_transit_enabled = true # CKV_OCI_4
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  source_details {
    source_type = "image"
    source_id   = var.image_ocid
  }

  platform_config {
    type                               = "AMD_VM" # SEV-SNP capable
    is_secure_boot_enabled             = true
    is_trusted_platform_module_enabled = true
    is_measured_boot_enabled           = true
    is_memory_encryption_enabled       = true
  }
}

resource "oci_core_instance" "frost_signer" {
  count               = 3
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[count.index % length(data.oci_identity_availability_domains.ads.availability_domains)].name
  compartment_id      = var.compartment_ocid
  display_name        = "frost-signer-${count.index + 1}"
  shape               = var.instance_shape

  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memory_gbs
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.frost_subnet[count.index].id
    assign_public_ip = false
    hostname_label   = "frostsigner${count.index + 1}"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = base64encode(local.frost_signer_cloud_init[count.index])
  }

  launch_options {
    is_pv_encryption_in_transit_enabled = true # CKV_OCI_4
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  source_details {
    source_type = "image"
    source_id   = var.image_ocid
  }

  platform_config {
    type                               = "AMD_VM" # SEV-SNP capable
    is_secure_boot_enabled             = true
    is_trusted_platform_module_enabled = true
    is_measured_boot_enabled           = true
    is_memory_encryption_enabled       = true
  }
}
