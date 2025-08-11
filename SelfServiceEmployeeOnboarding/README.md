# 👥 Self‑Service Employee Onboarding (YubiKey → Vault Identity → Kubernetes Namespace)  
> **Hardware token as the single source of truth for identity + infra provisioning**  
**Tech stack:** YubiKey • HashiCorp Vault Identity • Terraform Cloud • Kubernetes  

---

## 🎯 Goal
A new employee receives a **YubiKey**.  
When the YubiKey’s serial is registered in Vault, the system automatically:
1. Creates a Vault Identity entity with a policy (e.g., `k8s-read-secret`).
2. Maps the YubiKey serial to that entity.
3. Triggers Terraform Cloud to:
   - Create a Kubernetes namespace.
   - Create a ServiceAccount bound to the same Vault policy.

All driven by a single Terraform `null_resource` calling the Vault API.

---

## 🤔 Why it’s unexpected
Typical onboarding is manual or HR‑system driven.  
Here, the **hardware token itself is the source of truth** — once the serial is recorded, **identity + infra** appear automatically.

---

## ✅ Result
A single hardware token → Vault Identity → Kubernetes namespace, showing **“infrastructure‑as‑identity”** in action.

---

## 🏗 Architecture

```ascii
+--------------------+   (register)   +-------------------+
|  HR / IT (script)  |--------------->|  Vault            |
|  (YubiKey serial)  |                |  - Entity         |
+--------------------+                |  - Policy         |
                                      +-------------------+
                                                |
                                                |  Terraform Cloud webhook
                                                v
                                      +-------------------+
                                      |  Terraform Cloud |
                                      |  (creates NS)    |
                                      +-------------------+
```

---

## 📦 Prerequisites

| Component | Notes |
|-----------|-------|
| Vault     | Identity engine enabled |
| Terraform Cloud | Workspace with Kubernetes provider |
| Kubernetes | Cluster reachable from Terraform Cloud |
| yubico-piv-tool | For reading YubiKey serial |
| Python or Go | For registrar script |

---

## ⚙ Implementation

### **1️⃣ Vault Identity Setup**
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Enable userpass for demo logins
vault auth enable userpass

# Base policy to allow reading a secret (e.g., GitHub token)
vault policy write k8s-read-secret policies/k8s-read-secret.hcl
```

---

### **2️⃣ Terraform Cloud Workspace**
**`tf-onboard.tf`**:
```hcl
variable "yubikey_serial" {}

resource "kubernetes_namespace" "emp_ns" {
  metadata {
    name = "emp-${var.yubikey_serial}"
  }
}

resource "kubernetes_service_account" "emp_sa" {
  metadata {
    name      = "emp-${var.yubikey_serial}-sa"
    namespace = kubernetes_namespace.emp_ns.metadata[0].name
  }
}
```

---

### **3️⃣ Registrar Script (`register_yubikey.py`)**
**Purpose:**  
- Takes YubiKey serial number.  
- Calls Vault API to create Identity entity + alias.  
- Updates Git repo or triggers Terraform Cloud webhook.

```python
import sys, subprocess, requests, os

serial = sys.argv[1]
vault_addr = os.environ.get("VAULT_ADDR")
vault_token = os.environ.get("VAULT_TOKEN")

# Create entity
resp = requests.post(f"{vault_addr}/v1/identity/entity",
    headers={"X-Vault-Token": vault_token},
    json={"name": f"emp-{serial}", "policies": ["k8s-read-secret"]})
entity_id = resp.json()["data"]["id"]

# Create alias mapping
requests.post(f"{vault_addr}/v1/identity/entity-alias",
    headers={"X-Vault-Token": vault_token},
    json={"name": serial, "canonical_id": entity_id, "mount_accessor": "<yubikey_auth_accessor>"})

print(f"Registered YubiKey serial {serial} to entity {entity_id}")
```

Run after reading YubiKey serial:
```bash
SERIAL=$(yubico-piv-tool -a status | grep 'Serial number' | awk '{print $3}')
python3 register_yubikey.py $SERIAL
```

---

### **4️⃣ Wire to Terraform Cloud**
- In Terraform Cloud workspace **Variables**, set `yubikey_serial` to the just‑registered serial (or let script push `.tfvars` change).  
- Enable **Auto‑apply**.  
- Workspace runs → Namespace `emp-<entity-id>` + ServiceAccount created.  
- Optionally bind ServiceAccount to Vault via Kubernetes auth.

---

## 🧪 Demo

**1. Start Vault, enable identity, load policy**  
**2. Register YubiKey:**  
```bash
SERIAL=$(yubico-piv-tool -a status | grep 'Serial number' | awk '{print $3}')
python3 register_yubikey.py $SERIAL
```  
**3. Terraform Cloud auto‑runs** → new namespace `emp-<entity-id>` created  
**4. Verify:** Pod in namespace can read secret via Vault.


---
