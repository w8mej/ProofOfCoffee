# 🌐 YubiKey FIDO2 → Vault OIDC Auth → Terraform‑Provisioned Cloud‑Native Apps  
> **Hardware‑backed OIDC login feeding Terraform‑driven serverless deployments**  
**Tech stack:** YubiKey FIDO2 • Dex OIDC IdP • Vault OIDC • AWS Lambda • Terraform • Vault AWS/JWT Auth  

---

## 📜 Overview
**Core idea:**  
- Vault’s OIDC auth method trusts a self‑hosted **Dex** OIDC provider.  
- Dex uses **YubiKey FIDO2** as the primary authenticator.  
- Users log in with YubiKey Touch + FIDO2 → Dex issues OIDC token.  
- Vault exchanges OIDC token for Vault token.  
- Terraform uses Vault token to provision AWS Lambda + store secrets in Vault.  
- Lambda retrieves secret at runtime via Vault JWT/AWS auth.  

**You’ll walk away with:**  
- Password‑less, phishing‑resistant Vault login  
- Terraform‑provisioned serverless apps with dynamic secret access  
- End‑to‑end hardware‑backed trust chain  

---

## ✅ Security Benefits

| Feature | Benefit |
|---------|---------|
| **FIDO2 MFA** | Physical, phishing‑resistant authenticator for Vault login. |
| **Zero‑password** | No static credentials stored. |
| **Short‑lived Vault token** | OIDC token expires in ~1h; revocable instantly. |
| **Lambda JWT/AWS auth** | Lambda proves identity to Vault; no embedded secrets. |
| **Terraform‑driven** | Roles, policies, secret paths all version‑controlled. |

---

## 🏗 Architecture

```ascii
+-------------------+      +-------------------+      +-------------------+
|  YubiKey (FIDO2)  | ---> |   Dex (OIDC IdP)  | ---> |   Vault (OIDC)    |
+-------------------+      +-------------------+      +-------------------+
          ^                         ^                         |
          |                         |                         |
          |   Terraform (IaC)       |   Terraform (IaC)       |
          +-------------------------+-------------------------+
                                   |
                                   v
                         +-------------------+
                         |  AWS Lambda (App) |
                         +-------------------+
```

---

## 📦 Prerequisites

| Component | Version / Detail |
|-----------|------------------|
| Vault     | 1.15+ |
| Terraform | 1.7+ |
| Dex       | v2.38+ (Docker) |
| YubiKey   | 5 Series with FIDO2 |
| ykman fido | Latest |
| AWS CLI   | Configured for Lambda deployment |
| jq        | Optional |

---

## ⚙ Implementation

### **1️⃣ Deploy Dex with YubiKey FIDO2 Connector**
`dex.yml` – configure Yubico connector (requires Yubico developer account).  
Run Dex:
```bash
docker run -d -p 5556:5556 -p 5557:5557   -v $(pwd)/dex.yml:/etc/dex/config.yaml   ghcr.io/dexidp/dex:v2.38.0 serve /etc/dex/config.yaml
```

---

### **2️⃣ Configure Vault OIDC Auth**
```bash
vault auth enable oidc

vault write auth/oidc/config     oidc_discovery_url="http://localhost:5556/dex"     default_role="default"

vault write auth/oidc/role/default     bound_audiences="vault"     allowed_redirect_uris="http://127.0.0.1:8250/oidc/callback"     user_claim="email"     policies="default"
```

---

### **3️⃣ Login via OIDC**
```bash
vault login -method=oidc role=default
```
- Opens browser → YubiKey Touch + FIDO2 auth via Dex.  
- Returns `VAULT_TOKEN` bound to OIDC identity.

---

### **4️⃣ Terraform – Provision Lambda & Store Secret**
Example Terraform files:
```hcl
# provider.tf – configure Vault & AWS providers
# secret.tf – store API key in Vault
# lambda.tf – deploy AWS Lambda using zip
```

**Build Lambda package:**
```bash
# handler.py – fetch secret from Vault
zip lambda.zip handler.py
```

---

### **5️⃣ Configure Vault AWS Auth for Lambda**
```bash
vault auth enable aws

vault write auth/aws/role/lambda-role     auth_type=iam     bound_iam_principal_arn=arn:aws:iam::${AWS_ACCOUNT_ID}:role/lambda-vault-role     policies=default,lambda

vault policy write lambda lambda.hcl
```

---

### **6️⃣ Deploy with Terraform**
```bash
export TF_VAR_vault_token=$(vault login -method=oidc -format=json | jq -r .auth.client_token)
terraform init
terraform apply -auto-approve
```

---

### **7️⃣ Test Lambda**
```bash
aws lambda invoke --function-name vault-demo out.txt
cat out.txt
# → "Secret is: super-secret-api-key-123"
```

---


