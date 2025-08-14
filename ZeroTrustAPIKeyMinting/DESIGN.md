
# DESIGN — Zero-Trust API Key Minting with YubiKey Mutliple Party Compute, OCI KMS, TEEs, and Short-Lived Tokens

> **Status:** Prototype — for proof of coffee purposes (not for production).

## Goals & Threat Model
- **Self-service**: Engineers mint their own API keys without security team intervention.
- **Zero-trust & ephemeral**: All credentials are short-lived (5–60 minutes) and scoped.
- **Threshold control**: Root signing authority is split across multiple **YubiKey/HSM guardians**, plus an **OCI KMS** co-signature for receipts.
- **Hardware-backed trust**: Multi-party signing with **FROST Ed25519** threshold signatures, **OCI Confidential Compute SEV-SNP attestation**, and **mTLS** between signers.
- **No long-lived secrets**: Ephemeral JWTs; keys are never reconstructed in memory.

**Assumptions**
- Deployed on OCI OKE with private subnets, network policies, and service mesh enforcement.
- Signers run as **DaemonSets** in separate ADs/fault domains.
- Uses **cert-manager** for automatic mTLS rotation.

## Architecture (High Level)
```
+----------------+     /assert (WebAuthn) + /mint     +------------------+
| Engineer CLI   | ---------------------> |  Mint API        |
| (local loopback)|                       |  (FastAPI)       |
+----------------+ <--------------------- |  JWT + KMS sig   |
        ^                                    x-kms-sig header
        |                                            |
        |  JWT validate (Ed25519 + OCI KMS receipt)  |
        v                                            v
+------------------+      Threshold t-of-n      +---------------------+
| MPC Coordinator  | <------------------------> | FROST Signers       |
| (Deployment)     |    mTLS + JWT RPCs         | (DaemonSets, TEEs)  |
+------------------+                            +---------------------+
```

## Key Components & Data Flow
1. **Engineer enrollment** via `/register` → `/assert` (WebAuthn PIV attestation).
2. **Mint request**: CLI triggers `/assert` → `/mint` (bound to WebAuthn assertion).
3. **Attestation checks**:
   - **SEV-SNP** report verification (nonce bound to mint challenge).
   - AMI/OCID measurements + policy hash enforced.
4. **Threshold signing**:
   - Coordinator requests partial signatures from t-of-n signers via mTLS+JWT RPC.
   - Signers run in OCI Confidential VMs (CVMs) with FROST key shares.
5. **KMS co-signature**:
   - Coordinator calls OCI KMS to co-sign the JWT header → `x-kms-sig`.
   - Policy at service perimeter validates KMS signature.
6. **OPA/Rego enforcement**:
   - Envoy external authz calls OPA bundle → verifies scope, TTL, and `x-kms-sig`.
7. **Audit logging**:
   - Append-only, hash-chained log of mint events → OCI Logging + Object Storage (WORM).
8. **Abuse resistance**:
   - Replay detection for WebAuthn assertions (challenge + sign_count).
   - Per-identity rate limits, burst circuit-breakers for unusual requests.

## Security Controls
- **mTLS + JWT auth** between coordinator and signers.
- **NetworkPolicies**: only coordinator ↔ signer traffic on TCP/7000.
- **cert-manager** automated mTLS rotation.
- **OPA** policy bundles CI-tested and versioned.
- **KMS receipt** validation SDKs for Python, Go, Node.

## Operational Maturity
- p50/p95 latency SLOs for mint.
- Secrets hygiene: OCI Vault + Instance Principals.
- Disaster recovery: t-of-n share escrow and break-glass process with auto-expire.

## Compliance Mapping
- **PCI DSS**: Strong auth, no static PAN-equivalent secrets, short-lived keys.
- **SOC 2**: Hardware-backed key management, logging, and monitoring.
- **ISO 27001**: Controlled cryptographic key lifecycle.
- **NIST 800-63**: Multi-factor authentication, hardware-based assertions.

## Performance & Scale
- Benchmarked with vegeta: token issuance throughput across single and multi-region KMS.
- Scales with signer DaemonSets per AD.

## Deployment on OCI
- Terraform provisions OKE cluster, CVMs, subnets, and cert-manager.
- Coordinator & signers deployed via Kubernetes manifests/Helm.
- NetworkPolicies and service accounts enforce isolation.

## Replacing PoC Bits for Production
- Replace proof of coffee WebAuthn with production FIDO2 attestation validation.
- Integrate OCI KMS HSM keys directly for one share.
- Keep threshold signing fully in HSMs/TEEs; no key reconstruction.
- Enforce attestation at every RPC hop.
