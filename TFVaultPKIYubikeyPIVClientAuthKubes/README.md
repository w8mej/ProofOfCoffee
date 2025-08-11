# 🛡 Terraform‑Managed Vault PKI + YubiKey PIV for Client‑Certificate Authentication to Kubernetes  
> **Hardware‑backed mutual TLS for kubectl via Vault‑issued client certs**  
**Tech stack:** Terraform • HashiCorp Vault PKI • Kubernetes (Kind/EKS) • YubiKey PIV RSA • OpenSSL  

---

## 📜 Overview
**Core idea:**  
- Terraform creates a Vault PKI secrets engine (root + intermediate CAs).  
- Terraform provisions a Kubernetes cluster (Kind or EKS).  
- A YubiKey PIV RSA key (slot 9a) is used as the client certificate key for `kubectl`.  
- Vault signs the CSR generated from the YubiKey, issuing a cert valid **only** for that key.  
- `kubectl` authenticates using this hardware‑bound cert, achieving **mutual TLS** with the Kubernetes API server.  

**You’ll walk away with:**  
- A Vault‑managed PKI fully codified in Terraform  
- Hardware‑bound client certificate auth for Kubernetes  
- Short‑lived certs (e.g., 24h TTL) to limit exposure  

---

## ✅ Security Benefits

| Feature | Benefit |
|---------|---------|
| **Hardware‑bound private key** | Private key never leaves YubiKey; compromised workstation cannot impersonate. |
| **Vault‑issued intermediate** | Root CA remains offline; intermediates can be rotated independently. |
| **Terraform‑driven PKI** | CA creation, policies, and CRLs codified and version-controlled. |
| **Short‑lived client certs** | 24h TTL limits damage if cert leaks. |

---

## 🏗 Architecture

```ascii
+-------------------+    +-------------------+    +-------------------+
|  YubiKey (PIV)    |--> |   Vault PKI       |--> |  Kubernetes API   |
|  (RSA 2048)       |    | (root+intermediate|    |  Server (apiserver)|
+-------------------+    +-------------------+    +-------------------+
        ^                        ^                         ^
        |                        |                         |
        |   Terraform (IaC)      |   Terraform (IaC)       |
        +------------------------+-------------------------+
```

---

## 📦 Prerequisites

| Component | Version |
|-----------|---------|
| Vault     | 1.15+ |
| Terraform | 1.7+ |
| kubectl   | 1.28+ |
| yubico-piv-tool / ykman | Latest |
| Docker (Kind) or AWS CLI (EKS) | Installed & configured |
| OpenSSL   | Any recent version |

---

## ⚙ Implementation

### **1️⃣ Prepare YubiKey PIV (Slot 9a for Authentication)**
```bash
yubico-piv-tool -s 9a -a generate -o yubikey-auth.pem -k 2048
yubico-piv-tool -s 9a -a import -i yubikey-auth.pem
yubico-piv-tool -s 9a -a read-certificate -o yubikey-auth.crt
```

---

### **2️⃣ Terraform – Vault PKI Setup**
```hcl
# vault-pki.tf – define root CA, intermediate CA, roles, TTLs
```

---

### **3️⃣ Terraform – Kubernetes Cluster**
```hcl
# kind-cluster.tf – provision Kind cluster for demo
# For EKS, use aws_eks_cluster resources
```

---

### **4️⃣ Generate CSR from YubiKey and Sign via Vault**
```bash
# Export public key from slot 9a
yubico-piv-tool -s 9a -a read-certificate -o yubikey-auth.crt

# Create CSR using YubiKey private key (on token)
openssl req -new -key yubikey-auth.pem   -subj "/CN=kubectl-user"   -out yubikey.csr

# Terraform: sign-csr.tf – send CSR to Vault PKI for signing
```

---

### **5️⃣ Assemble kubeconfig with YubiKey‑derived Cert**
```bash
# Save signed cert
echo "${data.vault_generic_endpoint.client_cert.data.certificate}" > /tmp/k8s-client.crt

# Reference placeholder key file (actual key stays on YubiKey)
cp yubikey-auth.pem /tmp/k8s-client.key

# Generate kubeconfig
kubectl config set-cluster vault-demo   --server=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')   --certificate-authority=/etc/kubernetes/pki/ca.crt   --embed-certs=true

kubectl config set-credentials yubikey-user   --client-certificate=/tmp/k8s-client.crt   --client-key=/tmp/k8s-client.key

kubectl config set-context vault-demo   --cluster=vault-demo   --user=yubikey-user

kubectl config use-context vault-demo
```

---

### **6️⃣ Test kubectl Auth**
```bash
kubectl get nodes
# → Lists Kind/EKS nodes – authenticated via YubiKey-signed cert
```

---


