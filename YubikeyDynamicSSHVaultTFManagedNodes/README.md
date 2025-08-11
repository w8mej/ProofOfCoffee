# 🔐 YubiKey‑Protected Dynamic SSH Certificates via Vault + Terraform‑Managed Nodes  
> **OTP + PIV hardware protection for ephemeral SSH access**  
**Tech stack:** Terraform • HashiCorp Vault SSH CA • YubiKey OTP & PIV RSA • AWS EC2 • OpenSSH  

---

## 📜 Overview
**Core idea:**  
- YubiKey OTP is required to authenticate to Vault (via `yubikey` auth method).  
- Terraform provisions VMs (AWS EC2 in example) and requests **short‑lived SSH certificates** from Vault’s SSH CA.  
- SSH certificate is encrypted with a **data‑encryption key** stored only in YubiKey’s PIV slot (RSA‑2048).  
- User can SSH to any node without storing a private key on disk — key is extracted from YubiKey on‑the‑fly.  

**You’ll walk away with:**  
- Fully hardware‑protected SSH auth for Terraform‑managed nodes  
- Short‑lived, auto‑revoked SSH certs  
- No long‑term private key exposure  

---

## ✅ Security Benefits

| Feature | Why it matters |
|---------|----------------|
| **OTP‑first login** | Vault never uses a static password; OTP is single‑use & tied to physical YubiKey. |
| **PIV‑protected private key** | SSH private key never leaves token; even if host is compromised, key is safe. |
| **Dynamic short‑lived certs** | No long‑lived SSH keys; revocation automatic upon expiry. |
| **Terraform‑driven** | Provisioning + cert issuance codified and auditable. |

---

## 🏗 Architecture

```ascii
+-------------------+          +-------------------+          +-------------------+
|   YubiKey (OTP)   |  --->    |   Vault Server    |  <---    |   Terraform CLI   |
|   (PIV slot RSA)  |          |  (ssh_ca, yubikey|          |  (terraform apply)|
+-------------------+          |   auth, ssh)     |          +-------------------+
          ^                     +--------+----------+                     ^
          |                              |                              |
          |                              |                              |
          |                              v                              |
          |                     +-------------------+                    |
          +---------------------|  Provisioned EC2  |<-------------------+
                                |   (sshd)          |
                                +-------------------+
```

---

## 📦 Prerequisites

| Component      | Version / Detail |
|----------------|------------------|
| Vault          | 1.15+ (OSS OK) |
| Terraform      | 1.7+ |
| YubiKey        | 5 Series (OTP + PIV) |
| AWS CLI        | Configured IAM user for EC2 provisioning |
| yubico-piv-tool & ykman | Installed locally |
| ssh-keygen, ssh | OpenSSH 9.x |

---

## ⚙️ Implementation

### **1️⃣ Configure YubiKey for OTP & PIV**

**OTP (default slot):**
```bash
ykman otp static --generate  # Outputs a 44‑char secret
```

**PIV (RSA 2048 in slot 9c):**
```bash
yubico-piv-tool -s 9c -a generate -o yubikey-piv.pem -k 2048
yubico-piv-tool -s 9c -a import -i yubikey-piv.pem
yubico-piv-tool -s 9c -a read-certificate -o yubikey-piv.crt
```

---

### **2️⃣ Enable & Configure Vault YubiKey OTP Auth**
```bash
vault auth enable yubikey
vault write auth/yubikey/config     otp_secret=<BASE32>     otp_type=totp     ttl=10m
```

---

### **3️⃣ Create Vault SSH CA and Role**
```bash
vault secrets enable ssh

# Generate SSH CA keypair
vault write -field=public_key ssh/config/ca generate_signing_key=true > ca.pub

# Create role for issuing certs
vault write ssh/roles/terraform-ssh     key_type=ca     allow_user_certificates=true     allowed_users="*"     default_extensions='{"permit-pty": ""}'     ttl=30m
```

---

# -------------------------------------------------------------------
# Vault Environment & Initialization
# -------------------------------------------------------------------
# Purpose:
#   Set up Vault in development mode, initialize with a single unseal
#   key share, and log in as root to prepare for YubiKey OTP auth.
#
# Security Notes:
#   - Using 1 key share + threshold 1 is ONLY for testing/demo.
#   - Never store root tokens in plaintext in production scripts.
# -------------------------------------------------------------------

# Point Vault CLI to the local dev server
export VAULT_ADDR='http://127.0.0.1:8200'

# Initialize Vault (generates one unseal key and root token)
vault operator init -key-shares=1 -key-threshold=1

# Log in with the root token (printed by the init command)
vault login <root-token>

# -------------------------------------------------------------------
# Enable & Configure YubiKey Auth Method
# -------------------------------------------------------------------
# Purpose:
#   Enable Vault’s `yubikey` auth method and configure it to use
#   TOTP codes generated from a registered YubiKey.
#
# Workflow:
#   1. YubiKey generates a TOTP code from its secret seed.
#   2. Vault validates the code against its configured seed.
#   3. On success, Vault grants identity-mapped access.
#
# Prerequisites:
#   - A YubiKey programmed with a TOTP secret.
#   - The Base32-encoded OTP secret from the YubiKey setup step.
#
# Security Notes:
#   - `ttl=1h` limits token lifetime after successful login.
#   - Use strong secrets and rotate periodically.
# -------------------------------------------------------------------

# Enable the YubiKey auth method
vault auth enable yubikey

# Register the YubiKey's TOTP seed and configure parameters
vault write auth/yubikey/config \
    otp_secret=<BASE32_OTP_SECRET> \
    otp_type=totp \
    ttl=1h



### **4️⃣ Terraform Configuration**
```hcl
# versions.tf, provider.tf, main.tf
# Example: Provision EC2 instance + fetch SSH cert from Vault
```

---

### **5️⃣ Authenticate to Vault with YubiKey OTP**
```bash
OTP=$(ykman otp generate 1)  # Slot 1
VAULT_TOKEN=$(vault write -field=token auth/yubikey/login otp=$OTP)
export VAULT_TOKEN
```

---

### **6️⃣ Run Terraform**
```bash
terraform init
terraform apply -auto-approve
```
Terraform fetches SSH cert and stores it locally (encrypted).

---

### **7️⃣ Use SSH Cert – Decrypt with PIV On‑the‑Fly**
```bash
# Extract private key from YubiKey slot 9c
yubico-piv-tool -s 9c -a read -o /tmp/piv-key.pem

# Convert to OpenSSH format
ssh-keygen -p -m PEM -f /tmp/piv-key.pem -N "" -P "" -C "yubikey-piv"

# SSH into node
ssh -i /tmp/piv-key.pem     -o CertificateFile=$(terraform output -raw ssh_cert)     ec2-user@$(terraform output -raw demo_public_ip)
```

---


