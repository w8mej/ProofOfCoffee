# YubiKey‑Secured “Terraform‑Driven API Gateway” (PoC)

## 📌 Overview
This proof‑of‑concept demonstrates a **hardware‑secured API authentication flow** using:
- **Terraform** to generate API keys
- **HashiCorp Vault** to store only **hashed keys**
- **YubiKey (PIV)** to wrap and protect the plaintext key
- **FastAPI** as a minimal API gateway performing secure key validation

> ⚠️ **Note:** This is a proof of concept — it is **not production‑ready**. Use at your own risk.

### 🔑 What This Proves
- **Zero plaintext storage:** The API key is never stored server‑side in plaintext.
- **Hardware‑bound secrets:** Clients must have the physical YubiKey to unwrap the key.
- **Secure validation:** Gateway uses constant‑time hash comparison against Vault‑stored hash.

---

## 🔒 Security Notes
- Server stores **only a hash** of the API key; the client must possess the **physical YubiKey**.
- Use **short‑lived Vault tokens**; prefer OIDC or AppRole for CI/CD workflows.
- Always run behind **mTLS** in real environments.
- Rotate keys regularly and add **audit logging & alerting**.

---

## 🛠 Tech Stack
- **Terraform** – Infrastructure as Code for provisioning and Vault interactions
- **HashiCorp Vault** – Secure secret storage and key wrapping
- **YubiKey PIV** – Hardware encryption for API key distribution
- **FastAPI** – Lightweight API gateway

---

## 🚀 Quickstart

### 0️⃣ Prerequisites
- **Terraform** ≥ 1.5
- **Vault** dev server running
- **YubiKey** with PIV support
- CLI tools: `yubico-piv-tool`, `openssl`, `jq`
- Python ≥ 3.10 with `uvicorn`, `fastapi`, `hvac` installed
- Enable Vault KV if not already:
  ```bash
  vault secrets enable -path=kv kv-v2
  ```

---

### 1️⃣ Terraform: Generate & Register API Key (Hash Only)
```bash
export TF_VAR_vault_addr=http://127.0.0.1:8200
export TF_VAR_vault_token=root
export TF_VAR_app_name=myapp
export TF_VAR_client_pub_pem="$(yubico-piv-tool -s 9c -a read-certificate)"
make tf-apply
```

---

### 2️⃣ Client: Unwrap Key with YubiKey
```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
API_KEY=$(./scripts/unwrap_api_key.sh myapp)
```

---

### 3️⃣ Run the Gateway
```bash
cd gateway
pip install -r requirements.txt
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
export APP_NAME=myapp
uvicorn app:app --host 0.0.0.0 --port 8000
```

---

### 4️⃣ Call the API
```bash
curl -H "X-API-Key: $API_KEY" http://127.0.0.1:8000/secret-data
```
