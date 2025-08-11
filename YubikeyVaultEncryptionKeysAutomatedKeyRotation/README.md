# 🛡 YubiKey‑Protected Vault Encryption Keys for Terraform State + Automated Key Rotation  
> **Hardware-root-of-trust encryption for Terraform state with automatic post-deployment key rotation**  
**Tech stack:** Terraform • AWS S3 • HashiCorp Vault Transit • YubiKey PIV RSA • OpenSSL • AWS CLI • Lambda / Shell Script  

---

## 📜 Overview
**Core idea:**  
- Terraform state is encrypted with an **AES‑256 GCM key** managed by Vault Transit.  
- That AES key is **wrapped** with a YubiKey PIV RSA key (slot `9c`).  
- Terraform retrieves the wrapped key, unwraps it **inside the process** using the YubiKey (private key never leaves hardware).  
- After each `terraform apply`, the key is rotated automatically by Lambda or a local script — a fresh AES key is generated, wrapped with the YubiKey, and stored in Vault.  
- S3 bucket holds only encrypted state (no SSE‑KMS, no bucket key) — full encryption control remains with you.  

**You’ll walk away with:**  
- End-to-end state encryption under hardware control  
- Automated key rotation integrated into Terraform workflows  
- Compliance-ready, audit-logged encryption key lifecycle  

---

### **7️⃣ Verification**
Attempting to decrypt old state with the new key should fail (produces gibberish).

---

## ✅ Security Benefits

| Feature | Why it matters |
|---------|----------------|
| **YubiKey‑wrapped key** | Private RSA key never leaves hardware; attacker must possess the physical YubiKey. |
| **Vault‑managed** | Audit logs, RBAC, and versioning for key material. |
| **Automated rotation** | Limits exposure — each state version uses a unique key. |
| **No AWS‑managed KMS** | Full control over keys; meets compliance for customer-managed encryption. |
| **Terraform‑driven** | Key rotation integrated into normal apply workflow. |

---

## 📌 Summary Table

| PoC | Core Tech | YubiKey Feature | Vault Feature | Terraform Integration |
|-----|-----------|-----------------|---------------|-----------------------|
| 5   | YubiKey PIV (wrap) | RSA‑2048 | Transit (derived key) | State encryption + rotation |

---

**These patterns**:  
- Eliminate passwords with hardware-backed auth (OTP, FIDO2)  
- Provide fine-grained secret management (KV, Transit, DB, KV‑v2)  
- Enable dynamic, short-lived credentials  
- Secure Terraform state with hardware-root-of-trust  
- Ensure rotation + auditability via Vault + YubiKey  

---


## 🏗 Architecture

```ascii
+-------------------+        +-------------------+        +-------------------+
|   YubiKey (PIV)   |<------>|   Vault Transit   |<------>|  Terraform CLI    |
+-------------------+        +-------------------+        +-------------------+
        ^                           ^                         |
        |                           |                         |
        | Lambda / Script (rotate)  |     S3 bucket (state)   |
        +---------------------------+------------------------+
```

---

## 📦 Prerequisites

| Component      | Version / Notes |
|----------------|-----------------|
| Vault          | 1.15+ |
| Terraform      | 1.7+ |
| YubiKey        | PIV-capable (RSA‑2048) |
| AWS CLI + S3   | Configured for your state bucket |
| yubico-piv-tool / ykman | Installed locally |
| jq             | Optional |

---

## ⚙️ Implementation

### **1️⃣ Generate YubiKey RSA Key (slot 9c)**
```bash
yubico-piv-tool -s 9c -a generate -o yubikey-wrap.pem -k 2048
yubico-piv-tool -s 9c -a import -i yubikey-wrap.pem
yubico-piv-tool -s 9c -a read-certificate -o yubikey-wrap.crt
```

---

### **2️⃣ Enable Vault Transit and Create Derived AES Key**
```bash
vault secrets enable transit

vault write -f transit/keys/terraform-state     type=aes256-gcm96     derived=true
```

---

### **3️⃣ Generate and Wrap Initial Encryption Key**
```bash
# Generate random 32‑byte seed
SEED=$(openssl rand -base64 32)

# Derive AES key via Transit
ENCRYPTED_KEY=$(vault write -field=ciphertext transit/encrypt/terraform-state     plaintext=$(base64 -d <<<"$SEED" | base64))

# Wrap seed with YubiKey RSA OAEP
WRAPPED=$(echo -n "$SEED" |   openssl rsautl -encrypt -oaep     -inkey yubikey-wrap.pem -pubin -certin -in /dev/stdin | base64)

# Store wrapped seed in Vault KV
vault kv put kv/terraform/state key=$WRAPPED
```

**Result:**  
Vault stores the derived key, seed is stored wrapped by YubiKey.

---

### **4️⃣ Configure Terraform Backend (S3)**
```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = false
    kms_key_id     = null
  }
}
```

---

### **5️⃣ Wrapper Script to Unwrap Key and Apply**
```bash
# tf-wrapper.sh
WRAPPED=$(vault kv get -field=key kv/terraform/state | base64 -d)

# Unwrap with YubiKey (slot 9c)
SEED=$(echo "$WRAPPED" | openssl rsautl -decrypt -oaep     -inkey yubikey-wrap.pem)

# Derive AES key locally (Transit or OpenSSL)
LOCAL_KEY=$(...)  # your derivation logic

# Apply Terraform using local key for state encryption
terraform apply -auto-approve
```

After apply:
```bash
terraform state pull > tfstate.json
openssl enc -aes-256-gcm -pbkdf2     -in tfstate.json     -out tfstate.enc     -K $(echo "$LOCAL_KEY" | xxd -p -c 256)     -iv $(openssl rand -hex 12)

aws s3 cp tfstate.enc s3://my-terraform-state/prod/terraform.tfstate
```

---

### **6️⃣ Automated Key Rotation**
**rotate-key.sh**
```bash
# Generate new seed
NEW_SEED=$(openssl rand -base64 32)

# Wrap with YubiKey
NEW_WRAPPED=$(echo -n "$NEW_SEED" |   openssl rsautl -encrypt -oaep     -inkey yubikey-wrap.pem -pubin -certin | base64)

# Store in Vault
vault kv put kv/terraform/state key=$NEW_WRAPPED
```

Trigger after each apply:
```bash
terraform apply -auto-approve && ./rotate-key.sh
```

---

