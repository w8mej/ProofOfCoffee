# ☁️ Dynamic AWS Credentials via YubiKey‑PIV Login  
> **Password‑less, hardware‑rooted AWS provisioning with short‑lived Vault‑issued credentials**  
**Tech stack:** YubiKey PIV RSA • Vault PKI + Cert Auth • Vault AWS Secrets Engine • Terraform AWS Provider  

---

## 📜 Overview
**Core idea:**  
- Vault PKI issues short‑lived client certificates for YubiKey PIV keys.  
- Vault cert‑auth method maps certificate subject to an AWS‑access policy.  
- Vault AWS secrets engine assumes an IAM role for Terraform.  
- Terraform provisions AWS resources using **ephemeral AWS creds**.  
- Entire flow is password‑less and hardware‑rooted.

**You’ll walk away with:**  
- Hardware‑bound Vault login for AWS access  
- No long‑lived AWS keys in Terraform  
- Short‑lived, auditable AWS credentials

---

## ✅ Result
Terraform provisions AWS resources using **Vault‑issued 15‑minute creds**, authenticated via YubiKey client cert.  
No passwords. No static AWS keys.

---

## 🏗 Architecture

```ascii
+-------------------+   TLS client‑cert   +-------------------+
|  Operator laptop  |-------------------->|   Vault (TLS)     |
|  (YubiKey PIV)    |   (cert signed by   |   - cert auth     |
|                   |    Vault PKI)       |   - AWS secrets   |
+-------------------+                     +-------------------+
        |                                          |
        |  Terraform (aws provider)                |
        +------------------------------------------+
                  uses temporary AWS creds
```

---

## 📦 Prerequisites

| Component | Version |
|-----------|---------|
| Vault     | 1.15+ |
| Terraform | 1.7+ |
| YubiKey   | PIV‑capable |
| yubico-piv-tool | Latest |
| AWS CLI   | Configured IAM role |
| jq        | Optional |

---

## ⚙ Implementation

### **1️⃣ Vault PKI & Cert‑Auth Setup**

**`vault-pki.hcl`** (policy):
```hcl
path "pki*" {
  capabilities = ["create", "read", "update", "list", "delete"]
}
path "auth/cert/*" {
  capabilities = ["create", "read", "update", "list"]
}
```

```bash
vault policy write pki vault-pki.hcl

# Enable PKI
vault secrets enable -path=pki pki

vault write -field=certificate pki/root/generate/internal     common_name="Vault PKI Root" ttl=8760h > ca.pem

vault write pki/config/urls     issuing_certificates="http://127.0.0.1:8200/v1/pki/ca"     crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"

# Create role for YubiKey CSRs
vault write pki/roles/yubikey-client     allowed_domains="haxx.ninja"     allow_subdomains=true     max_ttl="720h"     ttl="720h"

# Enable cert auth
vault auth enable cert
vault write auth/cert/certs/operator     display_name="operator-yubikey"     policies="default,aws-terraform"     certificate=@ca.pem
```

---

### **2️⃣ Create YubiKey CSR & Get Signed by Vault**
```bash
# Generate key in slot 9c
yubico-piv-tool -s 9c -a generate -o yubikey_pub.pem

# Get YubiKey serial
SERIAL=$(yubico-piv-tool -a status | grep 'Serial number' | awk '{print $3}')

# Create CSR config
cat > yubikey.csr.cfg <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = yubikey-${SERIAL}.haxx.ninja
O = Acme Corp
EOF

# Request CSR
yubico-piv-tool -s 9c -a request-csr -i yubikey_pub.pem -o yubikey.csr -O yubikey.csr.cfg

# Sign CSR via Vault
vault write -format=json pki/sign/yubikey-client     csr=@yubikey.csr     common_name="yubikey-${SERIAL}.haxx.ninja"     ttl="720h" > signed.json

jq -r .data.certificate signed.json > yubikey_cert.pem
```

---

### **3️⃣ Vault Policy for AWS Creds**
**`aws-terraform.hcl`** – grants AWS secrets read:
```hcl
path "aws/creds/terraform-role" {
  capabilities = ["read"]
}
```
```bash
vault policy write aws-terraform aws-terraform.hcl
```

---

### **4️⃣ Vault AWS Secrets Engine & Role**
```bash
vault secrets enable -path=aws aws

vault write aws/config/root     access_key=AKIA...     secret_key=...

vault write aws/roles/terraform-role     credential_type=assumed_role     role_arn=arn:aws:iam::123456789012:role/vault-terraform     ttl=15m
```

---

### **5️⃣ Terraform Configuration**
Example:
```hcl
provider "vault" {}

data "vault_aws_access_credentials" "creds" {
  backend = "aws"
  role    = "terraform-role"
}

provider "aws" {
  access_key = data.vault_aws_access_credentials.creds.access_key
  secret_key = data.vault_aws_access_credentials.creds.secret_key
  region     = "us-east-1"
}
```

---

## 🧪 Demo
```bash
# Start Vault (dev mode)
docker run -d --name=vault -p 8200:8200   -e 'VAULT_DEV_ROOT_TOKEN_ID=root'   -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' hashicorp/vault

# Provision YubiKey & Vault configs
./provision-yubikey.sh

# Run Terraform without AWS creds in tfvars
terraform init
terraform apply
```

---