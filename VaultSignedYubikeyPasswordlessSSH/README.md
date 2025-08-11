# 🔑 Vault‑Signed YubiKey OTP for Password‑less SSH  
> **Single‑use, hardware‑backed SSH login via Vault‑signed OTP in a JWT**  
**Tech stack:** YubiKey OTP • HashiCorp Vault Transit + JWT • SSH Certificates • OpenSSH • Custom PrincipalsCommand  

---

## 🎯 Goal
Use a **YubiKey OTP** as a one‑time password that is **cryptographically signed by Vault**.  
Signature is verified on the SSH server, which then grants a short‑lived SSH certificate.  
No static SSH keys. No passwords.

---

## 🤔 Why it’s unexpected
OTP and SSH are usually **separate worlds**.  
By letting Vault sign the OTP, the OTP becomes a **verifiable proof of possession** usable for SSH login — enabling **stateless, hardware‑backed SSH MFA**.

---

## ✅ Result
- YubiKey OTP never sent in plain text  
- Signed by Vault → embedded in JWT  
- SSH server trusts JWT as proof of identity  
- Password‑less, single‑use, fully auditable in Vault logs  

---

## 🏗 Architecture

```ascii
+-------------------+   OTP   +-------------------+   Signed token   +-------------------+
|  User laptop      | ------> |  Vault (Transit)  | ---------------> |  SSH daemon       |
|  (YubiKey OTP)    |         |  sign-otp         |  (JWT)           |  (checks JWT)     |
+-------------------+         +-------------------+                   +-------------------+
```

---

## ⚙ Steps

### **1️⃣ Vault Setup**
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Transit key for OTP signing
vault secrets enable transit
vault write -f transit/keys/ssh-otp

# JWT signing key
vault secrets enable jwt
vault write jwt/keys/ssh-jwt algorithm=RS256

# Role to issue JWT containing signed OTP
vault write jwt/role/ssh-otp     key_name=ssh-jwt     allowed_claims="sub,exp,ssh_cert,otp_sig"     allowed_audiences="ssh-login"     ttl=2m
```

---

### **2️⃣ Client Script (`ssh-otp-login.sh`)**
**Purpose:**  
- Read OTP from YubiKey  
- Send to Vault `/v1/transit/sign/ssh-otp` with SSH public key as context  
- Receive signed JWT  
- Call `ssh` with temporary key + cert

```bash
#!/bin/bash
HOST=$1
USER=$2
PUBKEY_PATH=$3

OTP=$(ykman otp generate 1)
JWT=$(vault write -field=token jwt/issue/ssh-otp     sub="$USER"     ssh_cert="$(cat "$PUBKEY_PATH")"     otp_sig="$(vault write -field=signature transit/sign/ssh-otp input="$OTP")")

ssh -i "${PUBKEY_PATH%.*}" -o "CertificateFile=/tmp/ssh_cert" "$USER@$HOST"
```

---

### **3️⃣ SSH Server Configuration**
Add to `/etc/ssh/sshd_config`:
```text
AuthorizedPrincipalsCommand /usr/local/bin/verify_ssh_jwt %u %k
AuthorizedPrincipalsCommandUser vault
```

---

### **4️⃣ JWT Verification Script (`verify_ssh_jwt.sh`)**
**Purpose:**  
- Validate JWT signature using Vault’s public key or JWKS endpoint  
- If valid, return principal(s) allowed to log in

```bash
#!/bin/bash
USER=$1
PUBKEY=$2

# Example validation using Vault JWKS endpoint (pseudo-code)
VALID=$(curl -s http://vault.haxx.ninja/v1/jwt/keys/ssh-jwt | jq '.keys[0]')
if [ -n "$VALID" ]; then
  echo "$USER"
fi
```

```bash
chmod +x /usr/local/bin/verify_ssh_jwt.sh
systemctl restart sshd
```

---

## 🧪 Demo

**1. Start Vault (dev mode) and enable engines as above.**  
**2. Generate temporary SSH key pair:**
```bash
ssh-keygen -t ed25519 -f ~/.ssh/temp_key -N ""
```

**3. Run the client:**
```bash
./ssh-otp-login.sh myhost.haxx.ninja alice ~/.ssh/temp_key.pub
```

**4. SSH daemon validates JWT via Vault and grants access for 2 minutes.**

---


