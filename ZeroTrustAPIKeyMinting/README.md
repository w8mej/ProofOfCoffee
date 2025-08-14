# Zero-Trust API Key Minting with YubiKey MPC + Short-Lived Tokens (Python / Rust / Go / Node.js PoC)

**TL;DR:** Engineers self-mint **short-lived, scoped** JWTs signed by a rooted key via multiparty computation that is
**threshold-protected by YubiKey/HSM guardians**. No human bottlenecks, no long-lived secrets.

> ⚠️ **Prototype** — For proof of coffee purposes. Do **not** use in production.

---

## Why this exists
- **Velocity**: Engineers shouldn't wait on security to issue keys & credentials.
- **Risk boundaries**: Tokens expire in minutes and are scope-limited.
- **Zero trust**: Every mint goes through MPC guardianship and policy checks.

---

## LIMITED Security & Ops Assurances With Attestations

### LIMITED Cryptographic Protections
- **Threshold Signing (t-of-n)** – Signing authority split across multiple guardians; no single entity holds the complete key.
- **Ed25519 Signatures** – Modern, fast, deterministic signing algorithm with strong security properties.
- **YubiKey / HSM Integration** – Private key shares never leave hardware; signatures generated in secure hardware.
- **OCI KMS Approval** – An independent HSM approval gate ensures mints are cryptographically tied to a signed challenge.
- **OPA Policy Enforcement** – Scopes, TTLs, and role-based access controlled via JSON (`policy.json`) or fine-grained Rego policies.

### LIMITED Operational Hardening
- **Read-only Containers** – `read_only: true` and `cap_drop: ALL` in Docker Compose & Kubernetes manifests.
- **Non-root Execution** – API and signers run as UID 10001.
- **mTLS Between Services** – Certificates issued via cert-manager; Envoy SDS hot-reloads keys without downtime.
- **Network Policies** – Strict east-west restrictions in Kubernetes.
- **Health Probes** – Liveness/readiness endpoints with retry backoff.
- **Secrets Management** – No plaintext keys in repo; `.env` and Kubernetes secrets are placeholders only.

---

## Tunables (High-Level)

| Variable / Setting                  | Purpose                                                | Example / Default |
|--------------------------------------|--------------------------------------------------------|-------------------|
| `TOKEN_DEFAULT_TTL_SECONDS`          | Default token lifetime                                 | `900` (15 minutes)|
| `ALLOWED_SCOPES`                     | Comma-separated list of scopes allowed by default      | `read:logs,write:staging,deploy:canary` |
| `POLICY_FILE`                         | Path to JSON or Rego policy bundle                     | `./policy.json`   |
| `COORDINATOR_URL`                    | MPC coordinator endpoint                               | `http://127.0.0.1:8080` |
| `FROST_N` / `FROST_T`                 | FROST signer quorum size                               | `3` / `2`         |
| `REQUIRE_SNP_ATTESTATION`            | Enforce SEV-SNP for minting                            | `true` / `false`  |
| `USE_FROST`                           | Use FROST Ed25519 instead of key reconstruction        | `true` / `false`  |
| `OPA`                                 | Path to Open Policy Agent CLI                          | `opa`             |

---

## Repository Layout

```
├── certs/                     # Certificates & trust anchors for local/dev use
│   └── README.md               # How to generate/import certs
│
├── DESIGN.md                   # High-level architecture & threat model
├── docker-compose.yml          # Multi-service local stack (API, FROST signers, coordinator)
├── Dockerfile                  # Python API service container build definition
│
├── frost/                      # Rust-based FROST threshold signing components
│   ├── Cargo.toml               # Workspace manifest
│   ├── coordinator/            # FROST signing coordinator service
│   │   ├── Cargo.toml
│   │   ├── README.md
│   │   └── src/main.rs
│   ├── keygen/                  # FROST key generation utility
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── signer/                  # FROST signer node
│       ├── Cargo.toml
│       └── src/main.rs
│
├── infra/                      # Deployment infrastructure configs
│   ├── envoy/                   # Envoy proxy configs (mTLS, SDS)
│   │   ├── envoy-mtls-sds.yaml
│   │   └── envoy.yaml
│   └── terraform/               # OCI/Terraform infrastructure
│       ├── compute.tf
│       ├── frost_compute.tf
│       ├── frost_network.tf
│       ├── frost_outputs.tf
│       ├── kms.tf
│       ├── network.tf
│       ├── oke_network.tf
│       ├── oke.tf
│       ├── outputs.tf
│       ├── provider.tf
│       ├── README.md
│       └── variables.tf
│
├── k8s/                        # Kubernetes deployment manifests
│   ├── cert-manager/            # ClusterIssuer & cert resources
│   │   ├── cluster-issuers.yaml
│   │   └── frost-certs.yaml
│   └── frost/                   # FROST service deployments & networking
│       ├── coordinator.yaml
│       ├── daemonset.yaml
│       ├── limits-quota.yaml
│       ├── namespace.yaml
│       ├── networkpolicies.yaml
│       ├── secrets.example.yaml
│       └── service.yaml
│
├── LICENSE                     # License file
├── Makefile                    # Local dev/test, OPA policy, and k8s helpers
│
├── opa/                        # Standalone OPA policy modules
│   └── kms_sig_check.rego       # KMS signature receipt validation policy
│
├── policy/                     # Main OPA policy bundle for API authorization
│   ├── *.rego                   # Individual policy modules (JWT claims, scopes, mTLS, SEV-SNP, etc.)
│   ├── data.json                # Static policy data
│   ├── opa-config.yaml          # OPA server config
│   ├── README.md
│   └── tests/                   # Unit tests for each rego policy
│
├── policy.json                 # Simple JSON role/scope/TTL map for API
├── README.md                   # Top-level project overview & usage
├── requirements.txt            # Python dependency list (pinned)
├── results.json                # Example or cached result data
├── SECURITY.md                 # Security considerations, reporting process
│
├── src/                        # Python backend source
│   ├── attestation/             # Hardware/TEE attestation logic (AMD SEV-SNP)
│   ├── auth/                    # Authentication handlers (WebAuthn, PIV, engineer auth)
│   ├── cli/                     # CLI tools for minting & approvals
│   ├── issuer/                  # Token issuance & policy enforcement
│   ├── mpc/                     # MPC logic, coordinator client, HSM/YubiHSM integration
│   ├── oci/                     # OCI-specific KMS approval integration
│   └── server/                  # FastAPI app & WebAuthn API endpoints
│
├── static/                     # Static frontend assets
│   └── webauthn_demo.html       # Proof of Coffee page for WebAuthn flows
│
├── tests/                      # Python unit/integration tests
│   ├── test_frost_chaos.py      # Chaos/quorum test for ThresholdSigner
│   └── test_mint.py             # Placeholder mint test
│
├── verifiers/                   # Multi-lang verification tools for receipts/tokens
│   ├── go/main.go
│   ├── node/index.js
│   └── python/verifier.py
│
└── web/                         # Browser UI for PoC minting flow
    └── index.html
```

---

## Additional Feature Thoughts

- **WebAuthn Device Attestation** – Bind engineer identities to FIDO2 authenticators with device attestation.
- **FROST Signer Auto-Discovery** – Use Kubernetes DNS SRV records to dynamically discover signers.
- **Hash-Chained Logs** – Append-only log store for all mints with Merkle root verification.
- **Multi-Cloud KMS Approvals** – Support AWS KMS and GCP KMS in addition to OCI.
- **Advanced Scope Compositions** – Dynamically computed scopes from CI/CD context or runtime claims.
- **On-Demand Signer Scaling** – Spin up ephemeral signers in enclave-backed nodes only when needed.

---

## Future Operational Thoughts

1. **Replace PoC Share Storage**
   - Use secure HSMs or enclave-backed KMS instead of local volume-mounted share files.
   - Ensure no key material is reconstructable outside MPC protocol.

2. **Full SEV-SNP Chain Verification**
   - Validate AMD-signed VCEK certificates and revocation lists.
   - Bind mint policy hash to measured launch digest.

3. **OPA Bundle Distribution**
   - Sign and distribute OPA bundles from CI/CD artifact store.
   - Automate policy reload without downtime.

4. **Auditable KMS Receipts**
   - Store KMS receipts in tamper-evident append-only logs.
   - Include correlation IDs between API requests and KMS signatures.

5. **Rate Limiting & Abuse Prevention**
   - Integrate API rate limiting by IP + user identity.
   - Detect and block repeated failed approval attempts.

6. **CI/CD Integration**
   - Gate deploy jobs with freshly minted short-lived tokens.
   - Automatically scope tokens to service or environment.

7. **Zero-Downtime MPC Upgrades**
   - Rotate signer nodes or MPC parameters without downtime via overlapping quorum support.

---
