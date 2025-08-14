###############################################################################
# Terraform — OCI CVM bootstrap for Zero-Trust API Key Minting (documented)
#
# Security & Ops
# - Private instance only: no public IP assigned; place subnet behind NSG/SL with least-priv rules.
# - IMDS v1 is disabled; boot volume encryption-in-transit enabled; Secure Boot/TPM/Measured Boot on.
# - Cloud-Init pulls code and builds a container locally (PoC). In production, pull a **pinned digest**
#   from a private registry and avoid `git clone` on hosts.
# - Prefer instance principals for OCI access (no static creds). Restrict egress to Service Gateway.
#
# Tunables / Config
# - `var.instance_shape`, `var.ocpus`, `var.memory_gbs`: compute sizing.
# - `var.image_ocid`: base OS image (use OCI Confidential Compute-capable image).
# - `var.display_name`: resource naming.
# - `var.ssh_public_key`: injected for break-glass/ops access.
# - `local.cloud_init`: customize bootstrap; consider rendering with `templatefile()` for clarity.
#
# Improvements / Production
# - Replace Docker with containerd/nerdctl or use OKE (DaemonSets) for signers and coordinator.
# - Replace `git clone` + `docker build` with `docker pull ghcr.io/...@sha256:<digest>` and set
#   image policy admission to **digest-only**.
# - Add systemd unit for the selected binary (e.g., frost-signer) and health checks.
# - Lock outbound egress to Service Gateway, and route KMS/Object Storage via SGW (no NAT).
# - Ship logs to OCI Logging; emit attestation evidence at boot; verify SEV-SNP nonce binding.
###############################################################################

locals {
  # Cloud-Init: minimal PoC bootstrap
  # - Updates packages, installs docker, clones repo, builds container image locally.
  # - For production, PULL a pinned image and run it as a systemd service under a dedicated user.
  cloud_init = base64encode(<<EOF
#cloud-config
package_update: true
packages:
  - docker
  - git
runcmd:
  # add opc to docker group and start docker
  - [ sh, -c, "usermod -aG docker opc" ]
  - [ sh, -c, "systemctl enable docker && systemctl start docker" ]

  # create working dir with sane ownership
  - [ sh, -c, "mkdir -p /opt/mpc && chown opc:opc /opt/mpc" ]

  # PoC only: clone and build locally (avoid in prod; use pinned digest from private registry)
  - [ sh, -c, "cd /opt && git clone https://github.com/your-org/zero-trust-api-key-minting.git || true" ]
  - [ sh, -c, "cd /opt/zero-trust-api-key-minting && docker build --pull --no-cache -t ghcr.io/your-org/mpc-minting:latest ." ]

  # (Optional) example run command; in OKE this is managed by k8s instead
  # - [ sh, -c, "docker run --rm -d --name frost-coordinator -p 7100:7100 ghcr.io/your-org/mpc-minting:latest /usr/local/bin/frost-coordinator" ]
EOF
  )
}

# Discover Availability Domains; pick AD[0] below
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

resource "oci_core_instance" "cvm" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.compartment_ocid
  display_name        = var.display_name
  shape               = var.instance_shape

  # Flexible shape sizing
  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memory_gbs
  }

  # Private VNIC only; no public IP
  create_vnic_details {
    subnet_id        = oci_core_subnet.subnet.id
    assign_public_ip = false
    hostname_label   = "mpc-mint"
  }

  # SSH key + Cloud-Init user-data
  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = local.cloud_init
  }

  # Encrypt boot volume traffic instance<->volume (Checkov: CKV_OCI_4)
  launch_options {
    is_pv_encryption_in_transit_enabled = true
  }

  # Disable legacy metadata service (IMDS v1) (Checkov: CKV_OCI_5)
  metadata_service {
    are_legacy_imds_endpoints_disabled = true
  }

  # Base OS image (use Confidential VM capable image for SEV-SNP)
  source_details {
    source_type = "image"
    source_id   = var.image_ocid
  }

  # Confidential compute hardening
  platform_config {
    type                               = "AMD_VM" # AMD EPYC for SEV-SNP on OCI
    is_secure_boot_enabled             = true
    is_trusted_platform_module_enabled = true
    is_measured_boot_enabled           = true
    is_memory_encryption_enabled       = true
  }

  # (Optional) Freeform/defined tags for ownership/audit
  # freeform_tags = { "owner" = "security-eng", "purpose" = "mpc-mint-poc" }
}
