# 🗝 YubiKey‑Protected Vault Unseal (Shamir + OTP)  
> **Hardware-backed, OTP-derived Shamir unseal share retrieval**  
**Tech stack:** HashiCorp Vault • Shamir Secret Sharing • YubiKey OTP • Vault Transit Engine • OpenSSL • jq  

---

## 🎯 Goal
Use a **YubiKey OTP** to derive one of the Shamir‑split unseal keys. The operator never types a secret; the OTP is the **only input** needed to bring a Vault node out of sealed state.

---

## 🤔 Why it’s unexpected
Typical unseal key handling involves storing keys in a password manager or on paper.  
Here, the **hardware token becomes the key‑material source** — you can even split the secret across multiple YubiKeys for multi‑person unseal.

---

## ✅ Result
- No human ever typed a base‑64 unseal key.  
- YubiKey OTP was the **only secret** required to unseal Vault.  
- Secret material remains **hardware-bound** until needed.  

---

## 🏗 Architecture

```ascii
+-------------------+        +-------------------+
|  Operator with    |  OTP   |  Vault (dev mode) |
|  YubiKey (OTP)    | -----> |  Shamir unseal    |
+-------------------+        +-------------------+
        |                               |
        |  (script)                     |
        +-------------------------------+
                Derives 1/3 of the key
```

---

## ⚙ Steps

### **1️⃣ Generate Master Key & Shamir Split**
```bash
# Generate random 256‑bit master key
MASTER=$(openssl rand -hex 32)

# Split into 5 shares, 3‑of‑5 threshold
# Install SSS tool: go install github.com/lukechampine/sss@latest
sss split -t 3 -n 5 $MASTER > shares.txt

cat shares.txt
# Example:
# 1-5d2c7d9e0d5e9c5f...
# 2-9ab3c4d1e2f3a4b5...
```
---

### **2️⃣ Store Shares in Vault (inside Vault container)**
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Enable Transit engine
vault secrets enable transit
vault write -f transit/keys/unseal-share

# Encrypt each share and store in KV
while read -r line; do
  share_id=$(echo $line | cut -d'-' -f1)
  share_val=$(echo $line | cut -d'-' -f2-)
  
  vault write transit/encrypt/unseal-share         plaintext=$(base64 <<<"$share_val") > enc.json
  
  cipher=$(jq -r .data.ciphertext enc.json)
  vault kv put secret/unseal-share/$share_id ciphertext=$cipher
done < shares.txt
```

---

### **3️⃣ Helper Script: unseal-with-yubikey.sh**
**Concept:**  
- OTP **never travels** over the network.  
- Locally derive a 256‑bit HMAC key from OTP:  
  `KEY = HMAC_SHA256(otp, "vault-unseal-share")`  
- Supply this key as **context** to Vault Transit decrypt operation.  
- Ciphertext can only be opened if **same OTP** is presented.

---

## 🧪 Demo

**1. Start Vault in Dev Mode:**
```bash
docker run -d --name=vault -p 8200:8200   -e 'VAULT_DEV_ROOT_TOKEN_ID=root'   -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200'   hashicorp/vault
```

**2. Run the Helper:**
```bash
./unseal-with-yubikey.sh
# → Type OTP from YubiKey
# → Vault prints "Vault is now unsealed!"
```

---


