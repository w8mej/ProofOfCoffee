###############################################################################
# Terraform — Extra Private Subnets for OKE (documented)
#
# Security & Ops
# - Creates **private-only** subnets for OKE control-plane API, internal Service LB,
#   and node pools across 3 ADs. `prohibit_public_ip_on_vnic = true` prevents
#   public addresses on worker nodes and control-plane ENIs.
# - A single, shared **Security List (oke_sl)** is referenced by all OKE subnets.
#   For production, prefer **Network Security Groups (NSGs)** attached to the
#   OKE resources (API endpoint, LB, nodes) for fine-grained control and auditing.
# - Current `oke_sl` egress is `0.0.0.0/0` (all) and ingress allows **all TCP**
#   from `10.0.0.0/8`. This is acceptable for a *private lab/PoC*, but **tighten**
#   for production (see “Improvements / Production Hardening” below).
#
# Tunables / Config
# - Subnet CIDRs are derived from the VCN `/16` using `cidrsubnet(..., 8, idx)`.
#   Adjust size/indices if your VCN uses a different mask or is peered.
# - `oke_*` subnet roles (API, Service LB, nodes) reflect common OKE reference
#   architectures (private control plane + internal LBs).
# - Route table is currently `rt` (likely with IGW/NAT/SGW). For fully private,
#   attach **Service Gateway** and **NAT Gateway** routes and remove IGW exposure.
#
# Improvements / Production Hardening
# - Replace Security List with **NSGs** and author the minimal required ports:
#   • Nodes ↔ API: kubelet->APIServer 10250/6443 (cluster-internal), etcd only if applicable.
#   • Nodes ↔ Nodes: VXLAN/CNI ports (e.g., Calico: 4789/179; Cilium: 8472/4240 etc.).
#   • Nodes ↔ ServiceLB: health checks + backend ports only.
#   • Restrict egress to **Service Gateway** (KMS/Object Storage) + **NAT** for updates.
# - If you must keep SLs, narrow `ingress_security_rules` to **specific subnets/NSGs**
#   instead of a broad `10.0.0.0/8`. Consider adding **stateless** rules where safe.
# - Enable **Flow Logs** on subnets; export to Logging with WORM retention for forensics.
# - For compliance, add **Freeform/Defined tags** and guardrails (Terraform policies) to
#   block public IPs or broad ingress.
###############################################################################

# Private subnet for OKE control-plane API (no public IPs)
resource "oci_core_subnet" "private_api" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  cidr_block                 = cidrsubnet(oci_core_virtual_network.vcn.cidr_block, 8, 20)
  display_name               = "oke-private-api"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.oke_sl.id]
  dns_label                  = "okeapi"
}

# Private subnet for internal Service Load Balancers
resource "oci_core_subnet" "private_svclb" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  cidr_block                 = cidrsubnet(oci_core_virtual_network.vcn.cidr_block, 8, 21)
  display_name               = "oke-private-svclb"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.oke_sl.id]
  dns_label                  = "okesvclb"
}

# Private node subnets across 3 ADs (worker nodes / DaemonSets)
resource "oci_core_subnet" "private_nodes1" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  cidr_block                 = cidrsubnet(oci_core_virtual_network.vcn.cidr_block, 8, 22)
  display_name               = "oke-nodes-ad1"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.oke_sl.id]
  availability_domain        = data.oci_identity_availability_domains.ads.availability_domains[0].name
  dns_label                  = "oken1"
}

resource "oci_core_subnet" "private_nodes2" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  cidr_block                 = cidrsubnet(oci_core_virtual_network.vcn.cidr_block, 8, 23)
  display_name               = "oke-nodes-ad2"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.oke_sl.id]
  availability_domain        = data.oci_identity_availability_domains.ads.availability_domains[1].name
  dns_label                  = "oken2"
}

resource "oci_core_subnet" "private_nodes3" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  cidr_block                 = cidrsubnet(oci_core_virtual_network.vcn.cidr_block, 8, 24)
  display_name               = "oke-nodes-ad3"
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.oke_sl.id]
  availability_domain        = data.oci_identity_availability_domains.ads.availability_domains[2].name
  dns_label                  = "oken3"
}

# Shared Security List (PoC default)
# NOTE: Broad rules for quick cluster bring-up. Tighten or replace with NSGs in production.
resource "oci_core_security_list" "oke_sl" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_virtual_network.vcn.id
  display_name   = "oke-shared-sl"

  # Egress: all destinations/protocols (PoC). Prefer SGW/NAT-specific rules in prod.
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    description = "PoC: unrestricted egress. Replace with SGW/NAT-specific egress in production."
  }

  # Ingress: all TCP from RFC1918 /8 (PoC). Tighten in production (see below).
  ingress_security_rules {
    protocol = "6" # TCP
    source   = "10.0.0.0/8"

    tcp_options {
      min = 1
      max = 65535
    }

    description = "PoC: allow all TCP from 10.0.0.0/8. Replace with NSG/explicit ports in production."
  }

  # ---------------------------
  # Example hardened rules (commented)
  # ---------------------------
  # ingress_security_rules {
  #   protocol   = "6"
  #   source     = oci_core_subnet.private_api.cidr_block
  #   tcp_options { min = 10250 max = 10250 } # kubelet if needed
  #   description = "API -> nodes: kubelet"
  # }
  # ingress_security_rules {
  #   protocol   = "6"
  #   source     = oci_core_subnet.private_svclb.cidr_block
  #   tcp_options { min = 30000 max = 32767 } # NodePort range (if used)
  #   description = "Internal Service LB -> nodes: NodePorts"
  # }
  # ingress_security_rules {
  #   protocol   = "6"
  #   source     = oci_core_subnet.private_nodes1.cidr_block
  #   tcp_options { min = 4789 max = 4789 }   # VXLAN (Calico)
  #   description = "CNI overlay"
  # }
  # (repeat for other AD node subnets or use NSGs instead)
}
