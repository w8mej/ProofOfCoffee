# 🔐 Zero-Trust OCI Functions with YubiKey-Signed Terraform Plans  
> **Hardware-bound IaC Deployments with Auto-Revoked TLS**  
**Tech stack:** Terraform • OCI Functions • HashiCorp Vault PKI/AppRole • YubiKey PIV • OpenSSL • yubico-piv-tool • Python  

---

## 📜 Overview
**Core idea:**  
- Every Terraform plan is signed with a **YubiKey PIV certificate** — unsigned plans never exist in storage.  
- Vault PKI issues a **single-use TLS cert** for each OCI Function deployment — auto-revoked after update.  
- Functions execute **only if the TLS cert fingerprint matches the signed plan**, guaranteeing that only YubiKey-approved changes go live.  

**You’ll walk away with:**  
- A signed-plan CI/CD pipeline  
- Ephemeral TLS certs tied to specific deployments  
- Immutable audit chain from developer YubiKey → OCI runtime  

---


## ✅ Success Criteria

| Check | Command / Expected |
|-------|--------------------|
| Plan signature | `openssl dgst -sha256 -verify yubikey-piv.pub -signature tfplan.sig tfplan.bin` → `Verified OK` |
| Vault cert TTL | `vault read yubisign/cert/issue/function_cert` → `10m` |
| Function invocation | `curl -H "X-Plan-Fingerprint: <sha256>" https://<fn-url>` → `200 OK` |
| Tamper test | Modify plan → signature fails → Function rejects |

---

## 📌 Security Guarantees
- **No unsigned plan** is ever applied  
- **Ephemeral certs** prevent long-lived credential misuse  
- **Hardware-bound signatures** stop key theft from enabling deployments  

---

## 🏗 Architecture

```ascii
+-------------------+       +-------------------+       +-------------------+
|   Developer PC    |       |   HashiCorp Vault |       |   OCI Functions   |
| (Terraform +      |       |  (PKI + AppRole)  |       |  (HTTPS endpoint) |
|  YubiKey PIV)     |       |                   |       |                   |
+--------+----------+       +--------+----------+       +--------+----------+
         |                           |                           |
         | 1️⃣ Sign tfplan (PIV)      |                           |
         |-------------------------->|                           |
         |                           |                           |
         | 2️⃣ Terraform apply       |                           |
         |    (Vault AppRole)        |                           |
         |-------------------------->|                           |
         |                           | 3️⃣ Issue short-lived TLS |
         |                           |    cert for Function      |
         |                           |-------------------------->|
         |                           |                           |
         |                           | 4️⃣ Function validates TLS|
         |                           |    cert fingerprint       |
         |                           |<--------------------------|
```

---

## 📦 Prerequisites

| Component              | Version / Setting |
|------------------------|-------------------|
| OCI CLI & Terraform    | `terraform >= 1.7` |
| Vault Server           | `1.15+` (PKI, AppRole enabled) |
| YubiKey                | Model 5 (PIV) with signing key in slot `9a` |
| OpenSSL                | Any recent version |
| yubico-piv-tool        | Latest stable |
| jq, curl               | Installed locally |

---

## ⚙️ Implementation

### **1️⃣ Prepare YubiKey PIV Signing Slot**
```bash
# Generate keypair in slot 9a
yubico-piv-tool -s 9a -a generate -o yubikey-piv.crt -A RSA2048

# Export public key
yubico-piv-tool -a read-certificate -s 9a -o yubikey-piv.crt
openssl x509 -pubkey -noout -in yubikey-piv.crt > yubikey-piv.pub
```

---

### **2️⃣ Configure Vault PKI ("YubiSign" CA)**
```bash
# Generate intermediate CA
vault write yubisign/intermediate/generate/internal     common_name="yubikey-piv-intermediate"     ttl=8760h

# Load YubiKey certificate
vault write yubisign/intermediate/set-signed     certificate=@yubikey-piv.crt
```

---

### **3️⃣ Sign the Terraform Plan**
```bash
terraform plan -out=tfplan.bin

# Create SHA-256 digest
sha256sum tfplan.bin | awk '{print $1}' > tfplan.sha256

# Sign digest with YubiKey slot 9a
yubico-piv-tool -a sign-data -s 9a -i tfplan.sha256 -o tfplan.sig
```
**Artifacts:**  
- `tfplan.bin` — the plan  
- `tfplan.sig` — the signature  

---

### **4️⃣ Terraform Providers**
```hcl
# providers.tf
provider "oci" { ... }
provider "vault" { ... }
```

---

### **5️⃣ Vault AppRole for Terraform**
```hcl
# vault-approle.tf
resource "vault_approle_auth_backend_role" "terraform" { ... }
```
Export:
```bash
export VAULT_ROLE_ID=...
export VAULT_SECRET_ID=...
```

---

### **6️⃣ OCI Function TLS Cert Issuance**
```hcl
# oci-function.tf
resource "vault_pki_secret_backend_cert" "function_cert" { ... }
```

---

### **7️⃣ Runtime Validation (Function Code)**
```python
# handler.py
def handler(ctx, data: bytes):
    fingerprint = ctx.RequestHeader("X-Plan-Fingerprint")
    # Validate against TLS cert fingerprint issued by Vault
```

---

