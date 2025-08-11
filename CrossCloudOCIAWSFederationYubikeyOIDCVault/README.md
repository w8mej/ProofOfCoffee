# Cross‑Cloud Federation Hub (OCI ↔ AWS) Powered by YubiKey OIDC & Vault

## Goal
Use a **YubiKey FIDO2** WebAuthn authenticator for Vault OIDC login. The resulting short‑lived Vault OIDC token is fed to Terraform Cloud as a remote backend credential, creating a **single YubiKey identity** that can provision resources in both OCI and AWS.

Vault stores cross‑cloud secrets (AWS IAM keys, OCI DB passwords) and leases them to Terraform runs. All actions are recorded in a centralized audit log (stored in OCI Object Storage) and signed by the YubiKey.

## Why It’s Novel
- **Hardware‑rooted identity** spanning multiple clouds.
- **Single sign‑on** to Terraform Cloud via Vault OIDC backed by YubiKey FIDO2.
- **Centralized, immutable audit log** signed by the same YubiKey used for auth.
- **Cross‑cloud** provisioning from one identity source.

---

## Success Criteria

| Check | Expected Result |
|-------|-----------------|
| WebAuthn Login | Browser prompts YubiKey tap → Vault OIDC token returned |
| Vault Token TTL | ≤ 30 min |
| AWS & OCI Access | Resources created successfully |
| Signed Audit | Signature verifies against YubiKey public key |
| Immutable Log | OCI Object versioning shows write‑once |

---

## Architecture

```
+-------------------+          +-------------------+          +-------------------+
|   Developer PC    |          |   HashiCorp Vault |          |  Terraform Cloud  |
|   (Browser)       |          | (OIDC + PKI)      |          |  (Remote Backend) |
+--------+----------+          +--------+----------+          +--------+----------+
         |                               |                           |
   1️⃣ WebAuthn (FIDO2)                |                           |
   (YubiKey) ------------------------->|                           |
         |   OIDC Auth (Vault)          |                           |
         |<----------------------------|                           |
   2️⃣ Vault OIDC token (short‑lived)  |                           |
         |---------------------------->|                           |
         |   Injected as TF_VAR_VAULT_TOKEN                         |
         |                               |                           |
   3️⃣ Terraform plan/apply  --------->|   Vault secrets engine --> |
   (OCI + AWS)                          |   (AWS IAM, OCI DB)       |
         |                               |                           |
   4️⃣ Resources created in OCI & AWS                               |
         |                               |                           |
   5️⃣ Audit log (signed by YubiKey) ------------------------------>|
                                     Stored in OCI Object Storage
```

## Prerequisites

| Item | Version / Setting |
|------|-------------------|
| Vault Server | 1.15+ (OIDC, PKI, AWS & OCI secrets) |
| YubiKey | Model 5 (FIDO2/WebAuthn) |
| Terraform Cloud | Free/Team plan |
| OCI CLI & Terraform | terraform >= 1.7 |
| AWS CLI & Provider | aws >= 5.0 |
| Browser | Chrome/Firefox with WebAuthn |
| Utilities | jq, curl |

## Implementation Steps

### 1️⃣ Register YubiKey as FIDO2 WebAuthn Credential
1. Configure Keycloak (or Auth0) as an IdP with FIDO2 support.
2. Register Vault as an OIDC client (`vault-oidc`) in Keycloak with redirect URI:  
   `https://vault.haxx.ninja/ui/vault/auth/oidc/oidc/callback`.
3. Enroll the YubiKey in Keycloak: insert, tap, confirm registration.

> **Note:** Vault does not natively support WebAuthn; an external IdP is required.

### 2️⃣ Configure Vault OIDC Role
- Enable OIDC auth in Vault.
- Configure `auth/oidc/config` to point to Keycloak's discovery URL.
- Create a default role mapping to appropriate policies.

After successful WebAuthn login, Vault returns an OIDC JWT as `VAULT_TOKEN`.

### 3️⃣ Terraform Cloud Remote Backend
- Set Terraform Cloud workspace variables:  
  `VAULT_ADDR` = Vault URL, `VAULT_TOKEN` = empty (populated at run).
- Pre‑plan step: login via Vault OIDC in browser with YubiKey.
- Export the token to `TF_VAR_VAULT_TOKEN`.

```bash
export TF_VAR_VAULT_TOKEN=$(vault login -method=oidc -format=json | jq -r .auth.client_token)
```

### 4️⃣ Vault Secret Engines (AWS & OCI)
- Enable and configure AWS and OCI secrets engines in Vault.
- Store IAM and DB credentials with short TTLs.

### 5️⃣ Terraform Code
- Use Vault provider to fetch AWS & OCI credentials dynamically.
- Provision resources in both clouds in one run.

### 6️⃣ Immutable Audit Log (Signed by YubiKey)
Post‑apply Terraform Cloud run task:

```bash
terraform show -json > plan.json
fido2-token sign --key=slot=9a --input=plan.json --output=plan.sig
oci os object put   --bucket-name ${TF_VAR_AUDIT_BUCKET}   --name "audit/$(date +%s)-plan.json.sig"   --file plan.sig   --metadata '{"immutable":"true"}'
```

