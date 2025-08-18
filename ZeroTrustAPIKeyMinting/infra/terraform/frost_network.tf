###############################################################################
# Terraform — VCN Subnets (3x ADs) + Security Lists for FROST signers (documented)
#
# Security & Ops
# - Three **private subnets** across different Availability Domains to isolate signer CVMs
#   into separate **fault domains**. `prohibit_public_ip_on_vnic = true` prevents exposure.
# - **Least-privilege** Security Lists:
#     - Ingress only from a controlled CIDR (`var.allow_cidr`) to signer RPC ports (7000–7200) and SSH (22).
#     - Egress limited to VCN and **Oracle Services Network** (via Service Gateway) for KMS/Object Storage.
# - Pair with **Route Tables** that send 0.0.0.0/0 to NAT (if needed) and send OCI services to **Service Gateway**.
# - Prefer **Network Security Groups (NSGs)** for workload-level policy and to avoid coupling to subnet SLs.
#
# Tunables / Config
# - `var.allow_cidr`: CIDR allowed to reach signers (SSH + RPC). **Do not** set to 0.0.0.0/0.
# - Subnet CIDRs: derived from the VCN CIDR using `cidrsubnet(..., 8, 10|11|12)`. Adjust mask bits as needed.
# - Ports: RPC range 7000–7200 (FROST signer/coordinator) and SSH 22 for break-glass/ops.
#
# Improvements / Production
# - Replace Security Lists with **NSGs** and attach them to instances for finer control and auditing.
# - Add **Flow Logs** for subnets; ship to OCI Logging / SIEM.
# - Use **Private DNS** + **Service Gateway** for KMS/OSN; explicitly deny public egress if not required.
# - Add **stateful = false** (stateless) rules where appropriate for performance characteristics.
# - Consider per-environment allow_cidr (dev/staging/prod) and integrate with IPAM.
###############################################################################

# Three subnets across ADs for signer CVMs (private; no public IPs permitted)
resource "oci_core_subnet" "frost_subnet" {
  count                      = 3
  cidr_block                 = cidrsubnet(oci_core_virtual_network.vcn.cidr_block, 8, count.index + 10)
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_virtual_network.vcn.id
  display_name               = "frost-subnet-${count.index + 1}"
  prohibit_public_ip_on_vnic = true # Private-only subnets
  route_table_id             = oci_core_route_table.rt.id
  security_list_ids          = [oci_core_security_list.frost_sl[count.index].id]
  dns_label                  = "frost${count.index + 1}"
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[
    count.index % length(data.oci_identity_availability_domains.ads.availability_domains)
  ].name
}

# CIDR permitted to reach signer/keygen SSH & service ports.
# SECURITY: No default; must be explicitly set by the caller and must NOT be 0.0.0.0/0.
variable "allow_cidr" {
  description = "CIDR allowed to reach signer/keygen SSH & RPC ports (never 0.0.0.0/0)"
  type        = string

  validation {
    condition     = var.allow_cidr != "0.0.0.0/0"
    error_message = "allow_cidr must NOT be 0.0.0.0/0."
  }
}

# Security Lists per subnet (you can replace with NSGs for finer control)
resource "oci_core_security_list" "frost_sl" {
  count          = 3
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_virtual_network.vcn.id
  display_name   = "frost-sl-${count.index + 1}"

  # --------------------------
  # EGRESS — least privilege
  # --------------------------

  # Allow intra-VCN communication (signers <-> coordinator, observability, etc.)
  egress_security_rules {
    destination = oci_core_virtual_network.vcn.cidr_block
    protocol    = "all"
    description = "Allow egress within VCN"
  }

  # Allow egress to Oracle Services Network (via Service Gateway) for KMS, Object Storage, etc.
  egress_security_rules {
    destination      = "all-iad-services-in-oracle-services-network"
    destination_type = "SERVICE_CIDR_BLOCK"
    protocol         = "6" # TCP

    tcp_options {
      min = 443
      max = 443
    }

    description = "Allow egress to OCI services via Service Gateway (KMS, Object Storage)"
  }

  # (Optional) If NAT egress is required for package updates, add a controlled 0.0.0.0/0 TCP:80/443
  # egress_security_rules {
  #   destination = "0.0.0.0/0"
  #   protocol    = "6"
  #   tcp_options { min = 80 max = 443 }
  #   description = "Allow limited outbound HTTP/HTTPS via NAT (if required)"
  # }

  # --------------------------
  # INGRESS — restricted
  # --------------------------

  # RPC ports (Coordinator <-> Signers). Keep this narrow to specific coordinator CIDR(s) if possible.
  ingress_security_rules {
    protocol = "6" # TCP
    source   = var.allow_cidr

    tcp_options {
      min = 7000
      max = 7200
    }

    description = "Allow FROST signer/coordinator RPCs (7000–7200) from controlled CIDR"
  }

  # SSH: Break-glass/ops only, from controlled CIDR (never 0.0.0.0/0).
  ingress_security_rules {
    protocol = "6" # TCP
    source   = var.allow_cidr

    tcp_options {
      min = 22
      max = 22
    }

    description = "Allow SSH from controlled CIDR (ops access)"
  }
}
