# 🔑 YubiKey OTP‑Based Vault AppRole Login + Terraform‑Provisioned Dynamic Database Credentials  
> **MFA‑protected, password‑less dynamic database credential provisioning**  
**Tech stack:** Terraform • HashiCorp Vault AppRole • YubiKey OTP • PostgreSQL (Docker or AWS RDS) • Response‑Wrapping Tokens  

---

## 📜 Overview
**Core idea:**  
- YubiKey OTP is used as a **second factor** to obtain an AppRole `secret_id` from Vault via a custom `approle-otp` endpoint.  
- Terraform uses this AppRole to fetch **dynamic PostgreSQL credentials** from Vault and provision a DB instance.  
- OTP is **single-use** and `secret_id` expires in **5 minutes**, creating a short-lived, MFA-protected workflow for automated database provisioning.  

**You’ll walk away with:**  
- Password‑less database provisioning  
- Hardware‑backed MFA for Vault AppRole logins  
- Dynamic, auto‑revoked database credentials tied to Terraform runs  

---

## ✅ Security Benefits

| Feature | Why it matters |
|---------|----------------|
| **OTP‑protected AppRole** | Even if role‑ID leaks, attacker still needs valid YubiKey OTP to get secret‑ID. |
| **Response‑wrapping** | Secret‑ID is never exposed in plain text; single‑use & short‑lived. |
| **Dynamic DB credentials** | No static DB passwords; each Terraform run gets fresh, short‑lived credentials. |
| **Terraform‑driven revocation** | Destroying Terraform state revokes DB user automatically. |

---

## 🏗 Architecture

```ascii
+-------------------+       +-------------------+       +-------------------+
|   YubiKey (OTP)   |  -->  | Vault (AppRole)   |  -->  | PostgreSQL (RDS)  |
+-------------------+       +-------------------+       +-------------------+
          ^                         ^                         ^
          |                         |                         |
          |   Terraform (IaC)       |   Terraform (IaC)       |
          +-------------------------+-------------------------+
```

---

## 📦 Prerequisites

| Component      | Version / Notes |
|----------------|-----------------|
| Vault          | 1.15+ |
| Terraform      | 1.7+ |
| YubiKey        | OTP‑capable (any 5 Series) |
| PostgreSQL     | Docker image or AWS RDS access |
| ykman          | Latest version |
| jq             | Optional (JSON parsing) |

---

## ⚙️ Implementation

### **1️⃣ Enable YubiKey OTP Auth **
```bash
vault auth enable yubikey

vault write auth/yubikey/config     otp_secret=<BASE32>     otp_type=totp     ttl=10m
```

---

### **2️⃣ Create Vault AppRole & Policy**
```hcl
# approle.tf
resource "vault_approle_auth_backend_role" "db_provisioner" { ... }

resource "vault_policy" "db_access" { ... }
```
Policy grants access to `database/creds` endpoint.

---

### **3️⃣ Create OTP → Secret‑ID Exchange Endpoint**
- A **small script** or Lambda validates OTP, then issues a **response‑wrapped** secret‑ID.  
- TTL for wrapped token: **5 minutes**  
- One‑time unwrap ensures minimal exposure.  

```bash
# get-secret-id.sh
OTP=$(ykman oath accounts code <ACCOUNT_NAME> | awk '{print $2}')
WRAPPED_TOKEN=$(vault write -wrap-ttl=5m     auth/approle/login role_id=<ROLE_ID> otp="$OTP" | jq -r '.wrap_info.token')

echo "WRAPPED_TOKEN=$WRAPPED_TOKEN"
```

---

### **4️⃣ Terraform – Consume Wrapped Token**
```hcl
# variables.tf
variable "wrapped_token" {}

# provider.tf – AppRole auth
provider "vault" {
  auth_login {
    path = "auth/approle/login"
    parameters = {
      role_id   = "<ROLE_ID>"
      secret_id = data.vault_wrapping.unwrap.secret_id
    }
  }
}

# unwrap.tf
data "vault_wrapping" "unwrap" {
  token = var.wrapped_token
}
```

---

### **5️⃣ Provision PostgreSQL Instance**
For PoC, use Docker:
```hcl
# postgres.tf
resource "docker_container" "postgres" { ... }
```
Or AWS RDS with Terraform `aws_db_instance`.

---

### **6️⃣ Enable Vault Database Secrets Engine & Role**
```hcl
# db-engine.tf
resource "vault_database_secret_backend_connection" "pg" { ... }

resource "vault_database_secret_backend_role" "pg_role" {
  name     = "pg_dynamic_role"
  db_name  = vault_database_secret_backend_connection.pg.name
  creation_statements = ["CREATE ROLE ..."]
  default_ttl = "1h"
  max_ttl     = "24h"
}
```

---

### **7️⃣ Retrieve Dynamic Credentials**
```hcl
# dynamic-db-creds.tf
data "vault_database_credentials" "pg_creds" {
  name = vault_database_secret_backend_role.pg_role.name
}
```

Terraform will output:
```hcl
output "db_username" { value = data.vault_database_credentials.pg_creds.username }
output "db_password" { value = data.vault_database_credentials.pg_creds.password }
```

---

### **8️⃣ Run the Workflow**
```bash
# Step 1: Generate OTP & wrap secret_id
./get-secret-id.sh   # → WRAPPED_TOKEN=...

# Step 2: Feed token to Terraform
export TF_VAR_wrapped_token="s.xxxxxxxx"
terraform init
terraform apply -auto-approve
```

