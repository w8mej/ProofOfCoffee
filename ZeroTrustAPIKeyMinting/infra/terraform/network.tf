###############################################################################
# Terraform — OCI Networking for MPC Minting Environment
#
# Security & Ops
# - Creates an **isolated Virtual Cloud Network (VCN)** for MPC minting workloads.
# - **Internet Gateway** allows outbound access for updates, builds, or
#   integrations (can be removed if using private endpoints only).
# - **Route Table** routes 0.0.0.0/0 traffic to IGW.
# - **Subnet** for CVMs / container hosts running minting services.
# - **Security List**:
#     • Egress: unrestricted (all protocols, all destinations).
#     • Ingress: TCP 8080 restricted to `var.allow_cidr` (never 0.0.0.0/0).
# - CIDRs chosen to avoid overlap with common RFC1918 space in other networks.
#
# Tunables / Config
# - `cidr_block`: Change if your on-prem or other cloud networks overlap.
# - `subnet_cidr`: Adjust based on expected pod/VM density per subnet.
# - `prohibit_public_ip_on_vnic`: Set to `true` for private-only workloads.
# - `allow_cidr`: Restrict ingress source to specific admin or service ranges.
# - `tcp_options`: Change ports if API binds somewhere other than 8080.
#
# Potential Improvements
# - Replace IGW + public IPs with **NAT Gateway** + **Service Gateway** to keep
#   instances private while still allowing OCI service access.
# - Add **Network Security Groups (NSGs)** for more granular, per-VM ACLs.
# - Split workloads into multiple subnets for security tiering (e.g., API, DB).
# - Restrict egress to known destinations to mitigate exfiltration risk.
#
# Production Hardening Ideas
# - Disable `prohibit_public_ip_on_vnic = false` unless absolutely necessary.
# - Implement **Flow Logs** for the subnet and regularly review traffic patterns.
# - Integrate with OCI WAF or front API traffic via a load balancer.
# - Remove IGW entirely and rely on private connectivity (FastConnect/VPN).
###############################################################################

resource "oci_core_virtual_network" "vcn" {
  cidr_block     = "10.10.0.0/16"
  compartment_id = var.compartment_ocid
  display_name   = "mpc-minting-vcn"
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = var.compartment_ocid
  display_name   = "mpc-minting-igw"
  vcn_id         = oci_core_virtual_network.vcn.id
  enabled        = true
}

resource "oci_core_route_table" "rt" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_virtual_network.vcn.id
  display_name   = "mpc-minting-rt"
  route_rules {
    network_entity_id = oci_core_internet_gateway.igw.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

resource "oci_core_subnet" "subnet" {
  cidr_block                 = var.subnet_cidr
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  display_name               = "mpc-minting-subnet"
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.sl.id]
  dns_label                  = "mpcmint"
}

resource "oci_core_security_list" "sl" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_virtual_network.vcn.id
  display_name   = "mpc-minting-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol = "6"
    source   = var.allow_cidr
    tcp_options {
      min = 8080
      max = 8080
    }
  }
}
