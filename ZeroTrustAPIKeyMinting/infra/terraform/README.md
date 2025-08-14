# Terraform — OCI Confidential VM for Mint API (PoC)

This Terraform configuration provisions an **Oracle Cloud Infrastructure (OCI) Confidential VM** to host a Mint API proof-of-concept.  
It is designed to run inside a secure environment using **AMD SEV-SNP** with **Secure Boot**, **Measured Boot**, and **Memory Encryption** enabled.

---

## 🚀 Deployment Overview

**Resources Created:**
- **VCN** — Virtual Cloud Network (`10.10.0.0/16`)
- **Public Subnet** — CIDR block `10.10.0.0/24` for the Confidential VM
- **Internet Gateway (IGW)** — Enables egress to the internet
- **Route Table** — Routes `0.0.0.0/0` traffic via IGW
- **Security List** — Restricts inbound traffic to:
  - TCP **8080** from `allow_cidr`
  - Full egress allowed
- **Confidential VM (AMD SEV-SNP)** — Configured with:
  - **Docker** installed via cloud-init
  - **Mint API** cloned from GitHub and built inside Docker
  - **Secure Boot**, **Measured Boot**, **TPM**, **Memory Encryption**

---

## 📦 Usage

1. **Set variables** in `terraform.tfvars`:
    ```hcl
    tenancy_ocid      = "ocid1.tenancy.oc1..xxx"
    user_ocid         = "ocid1.user.oc1..xxx"
    fingerprint       = "aa:bb:cc:..."
    private_key_path  = "~/.oci/oci_api_key.pem"
    compartment_ocid  = "ocid1.compartment.oc1..xxx"
    region            = "us-phoenix-1"
    ssh_public_key    = "ssh-ed25519 AAAA..."
    image_ocid        = "ocid1.image.oc1.phx...." # Oracle Linux 8 or 9 (check compatible)
    ```

2. **Initialize Terraform**:
    ```bash
    terraform init
    ```

3. **Apply the configuration**:
    ```bash
    terraform apply
    ```

4. **Access the VM** (SSH from an IP within `allow_cidr`):
    ```bash
    ssh -i ~/.ssh/id_ed25519 opc@<public_ip>
    ```

---

## 🔒 Security Notes

- **Confidential Computing** is enforced with:
  - `is_memory_encryption_enabled = true`
  - `is_secure_boot_enabled = true`
  - `is_trusted_platform_module_enabled = true`
  - `is_measured_boot_enabled = true`
- **No public IPs** unless explicitly configured for the subnet.
- **SSH access** is restricted to the CIDR defined in `allow_cidr`.

---

## 📜 cloud-init Behavior

Upon instance creation:
1. Installs **Docker** and **Git**
2. Adds the `opc` user to the Docker group
3. Clones the Mint API repository:
    ```
    /opt/zero-trust-api-key-minting
    ```
4. Builds the Mint API container:
    ```bash
    docker build -t ghcr.io/your-org/mpc-minting:latest .
    ```

---

## 🗺 Architecture Diagram

```
[ Admin Workstation ]
        |
   (SSH 22/TCP from allow_cidr)
        |
[ OCI VCN 10.10.0.0/16 ]
        |
 ┌────────────────────────────────────────────┐
 │ Subnet: 10.10.0.0/24                        │
 │  - Confidential VM (Mint API)               │
 │  - Secure Boot, TPM, Measured Boot           │
 │  - Memory Encryption Enabled                 │
 └────────────────────────────────────────────┘
        |
[ Internet Gateway ] ←→ Public Internet
```

---

## 🧹 Cleanup

To remove all resources:
```bash
terraform destroy
```

---

## 📌 Notes

- Tested with **Terraform v1.6.0+** and **OCI Provider v7.13.0+**.
- Adjust CIDRs, shapes, and `allow_cidr` to match your environment.
