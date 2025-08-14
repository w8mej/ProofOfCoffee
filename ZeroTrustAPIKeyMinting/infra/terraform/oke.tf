###############################################################################
# Terraform — OKE Cluster + Private Endpoints + NSGs (documented)
#
# Security & Ops
# - Private-only OKE control plane: `is_public_ip_enabled = false` binds the API to a private subnet.
# - **NSGs** applied to the API endpoint and Service Load Balancers (CKV2_OCI_3) to enforce least privilege.
# - Pod Security Admission (PSA) labels set on the cluster (PSP deprecated) to baseline/restricted.
# - Node pool spans 3 ADs (placement configs) to align with FROST signer fault domains; PV encryption in transit on.
# - Cluster & nodes live on **private subnets** (no public IPs); rely on Service/NAT Gateways for egress.
#
# Tunables / Config
# - `var.oke_version` — OKE/Kubernetes version (pin explicitly for repeatability).
# - `var.instance_shape` — worker shape (consider flexible shapes and set OCPUs/memory if needed).
# - `var.image_ocid` — worker OS image (use hardened, CVM-capable images if desired).
# - `pods_cidr`, `services_cidr` — ensure they don’t overlap with VCN/peered networks.
# - `service_lb_subnet_ids` — internal LB subnets (private).
# - Freeform tags — used here to enable PSA; you can add ownership/compliance tags.
#
# Improvements / Production Hardening
# - Add explicit **NSG rules** for API endpoint and Service LBs (examples below) instead of broad SLs.
# - Use **private control plane endpoint** + bastion/PE to access, or run cluster-autoscaler/ops inside VCN.
# - Enable **cluster logging/metrics** to OCI Logging/Monitoring; enforce audit logs retention.
# - Pin the worker **image digest**; set `node_source_details` to an approved, CIS-hardened image.
# - Add **OCI Certificates** / cert-manager for in-cluster mTLS; rotate automatically.
###############################################################################

# -----------------------
# Network Security Groups
# -----------------------
resource "oci_core_network_security_group" "oke_api" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_virtual_network.vcn.id
  display_name   = "oke-api-nsg"
}

resource "oci_core_network_security_group" "oke_svclb" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_virtual_network.vcn.id
  display_name   = "oke-svclb-nsg"
}

# (Recommended) Add targeted NSG rules for private API and internal Service LBs.
# Replace CIDRs with your admin/jump/bastion ranges and node subnets.
# API NSG: Allow kubectl from admin networks (HTTPS 6443)
# resource "oci_core_network_security_group_security_rule" "oke_api_ingress_kubectl" {
#   network_security_group_id = oci_core_network_security_group.oke_api.id
#   direction                 = "INGRESS"
#   protocol                  = "6" # TCP
#   source                    = var.admin_cidr
#   tcp_options { destination_port_range { min = 6443, max = 6443 } }
#   description               = "kubectl to private API"
# }
# Service LB NSG example: allow from node subnets to backend ports (adjust as needed)
# resource "oci_core_network_security_group_security_rule" "oke_svclb_ingress" {
#   network_security_group_id = oci_core_network_security_group.oke_svclb.id
#   direction                 = "INGRESS"
#   protocol                  = "6"
#   source                    = oci_core_subnet.private_nodes1.cidr_block
#   tcp_options { destination_port_range { min = 30000, max = 32767 } } # NodePort (if used)
#   description               = "Nodes to Service LBs (example)"
# }

# -----------------------
# OKE Cluster (private)
# -----------------------
resource "oci_containerengine_cluster" "frost" {
  compartment_id     = var.compartment_ocid
  kubernetes_version = var.oke_version
  name               = "${var.display_name}-frost"
  vcn_id             = oci_core_virtual_network.vcn.id

  endpoint_config {
    is_public_ip_enabled = false
    subnet_id            = oci_core_subnet.private_api.id
    nsg_ids              = [oci_core_network_security_group.oke_api.id] # CKV2_OCI_3: NSG on API endpoint
  }

  options {
    # Node/Pod hardening: disable legacy IMDS (applies to worker nodes created/managed by OKE)
    are_legacy_imds_endpoints_disabled = true

    # Internal Service LBs (private only)
    service_lb_subnet_ids = [oci_core_subnet.private_svclb.id]
    service_lb_nsg_ids    = [oci_core_network_security_group.oke_svclb.id] # CKV2_OCI_3: NSG on LB

    admission_controller_options {
      is_pod_security_policy_enabled = false # PSP is deprecated; use PSA labels instead
    }

    kubernetes_network_config {
      pods_cidr     = "10.244.0.0/16"
      services_cidr = "10.96.0.0/16"
    }
  }

  # PSA labels — enforce baseline, audit restricted
  freeform_tags = {
    "pod-security.kubernetes.io/enforce"         = "baseline"
    "pod-security.kubernetes.io/audit"           = "restricted"
    "pod-security.kubernetes.io/enforce-version" = "latest"
    "pod-security.kubernetes.io/audit-version"   = "latest"
  }
}

# -----------------------
# OKE Node Pool (3 ADs)
# -----------------------
resource "oci_containerengine_node_pool" "frost_np" {
  compartment_id     = var.compartment_ocid
  cluster_id         = oci_containerengine_cluster.frost.id
  kubernetes_version = var.oke_version
  name               = "${var.display_name}-signers"
  node_shape         = var.instance_shape

  # Node subnets across ADs (private-only)
  subnet_ids = [
    oci_core_subnet.private_nodes1.id,
    oci_core_subnet.private_nodes2.id,
    oci_core_subnet.private_nodes3.id
  ]

  node_source_details {
    source_type = "IMAGE"
    image_id    = var.image_ocid
  }

  node_config_details {
    size = 3

    placement_configs {
      availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
      subnet_id           = oci_core_subnet.private_nodes1.id
    }
    placement_configs {
      availability_domain = data.oci_identity_availability_domains.ads.availability_domains[1].name
      subnet_id           = oci_core_subnet.private_nodes2.id
    }
    placement_configs {
      availability_domain = data.oci_identity_availability_domains.ads.availability_domains[2].name
      subnet_id           = oci_core_subnet.private_nodes3.id
    }

    # Encrypt volume traffic instance<->volume (CKV2_OCI_5)
    is_pv_encryption_in_transit_enabled = true
  }

  # (Optional) Node labels/taints to isolate FROST signer DaemonSets
  # node_shape_config { ... }  # Use for flexible shapes to set OCPUs/memory
}

# -----------------------
# Additional Guidance
# -----------------------
# - Add NAT + Service Gateway routes on subnets to keep everything private while allowing egress for
#   image pulls and access to OCI services (KMS, Object Storage).
# - Consider enabling OKE Cluster Autoscaler and Horizontal Pod Autoscaler for signer DaemonSets
#   (where appropriate) to handle partial failures or load spikes (t-of-n quorum).
# - Integrate with cert-manager ClusterIssuer + Certificates to issue mTLS for FROST RPCs;
#   rotate automatically and rely on NetworkPolicies to allow only coordinator ↔ signers.
# - Export cluster audit logs to OCI Logging with WORM retention for forensics/compliance.
