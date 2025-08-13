# MPC Ephemeral Signing — Python gRPC + Protobuf Proof of Concept (TEE-Attested on OCI Confidential Compute)

## Overview
This proof-of-concept (POC) demonstrates how multiple independent parties can **approve and sign artifacts** using a **Multi-Party Computation (MPC)** pattern, **short-lived certificates**, and **hardware-backed attestation** in **Oracle Cloud Infrastructure (OCI) Confidential Computing enclaves**.

While the cryptographic core is simplified (single Ed25519 key vs. true MPC/FROST), the **service orchestration, trust model, and attestation plumbing are production-oriented** — making it straightforward to swap in a real threshold-signature backend later.

---

## Goals of This POC
- **Simulate MPC artifact signing** using a quorum of *engineers* and *stewards*.
- **Enforce hardware trust guarantees** with AMD SEV-SNP attestation in OCI Confidential VMs.
- **Mint ephemeral code-signing certificates** tied to session state, participants, and enclave identity.
- **Log signed artifacts** in a transparency log for auditability.
- **Provide a gRPC + Protobuf microservice framework** that can be hardened for production.

---

## Security & Operations Notes
- **Defense-in-depth**: mTLS + SNP attestation for mutual identity and integrity.
- **Replay Protection**: Fresh nonce per attestation bound into `report_data`.
- **Policy Pinning**: All RPCs fail if `TEE_POLICY_HASH` mismatches.
- **Auditing**: Interceptors log user, method, attestation digest, and session.
- **Secrets Management**: Store TLS certs and policy hash in OCI Vault with rotation.

---

## Tunables
| Variable | Purpose |
|----------|---------|
| `TEE_POLICY_HASH` | Hex-encoded SHA-256 of allowed enclave measurement |
| `REQUIRED_ENGINEERS` / `REQUIRED_STEWARDS` | Quorum counts for Coordinator |
| `*_TLS_CERT` / `*_TLS_KEY` | TLS certs for mTLS |
| `CLIENT_TLS_CA` / `CLIENT_TLS_CERT` / `CLIENT_TLS_KEY` | Client mTLS settings |

---

## Path to Production
To make this production-ready:
- Replace `MockThresholdEngine` with a **true MPC/FROST threshold signer** (distributed keygen, hardware-wrapped shares).
- Use **OCI Vault / HSM** for key custody.
- Replace in-memory TLog with a **Merkle-tree-backed transparency log**.
- Integrate **real WebAuthn** for participant identity verification.
- Enforce **policy and role management** in a persistent datastore.

---


## Architecture
The POC is split into four gRPC microservices:

1. **Coordinator** – Orchestrates sessions, tracks approvals, triggers signing once quorum is met.
2. **Ephemeral CA** – Issues short-lived code-signing certificates bound to the enclave’s measured state and session metadata.
3. **Transparency Log** – Stores immutable records of signed artifacts (in-memory for POC).
4. **AuthN Service** – Verifies participant identity (demo WebAuthn token in this POC).

Clients interact with these services via a Python CLI (`clients/cli.py`).

---

## Security Model
- **mTLS** — Authenticates *who* is talking to whom.
- **SNP Attestation** — Proves *where and how* the code is running (enforced on every RPC).
- **Ephemeral Keys** — No long-term private signing keys; each session is isolated.
- **Quorum Enforcement** — Only proceeds when the configured number of engineers and stewards have approved.
- **Transparency Logging** — Signed artifacts and associated metadata are published for audit.

---

## What This POC Is Not
- **Not real MPC** — The threshold signing here is simulated (approval → single key sign).  
  Replace `common/mpc_provider.py` with a true MPC/FROST implementation to achieve actual distributed key control.
- **Not production-secure storage** — Keys are in memory; no HSM/KMS binding.
- **Not a tamper-evident log** — The TLog is in-memory; replace with Merkle-tree-backed (e.g., Rekor).

---

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m grpc_tools.protoc -I proto proto/mpc.proto     --python_out=gen --grpc_python_out=gen
```

---

## Running the Services (Four Terminals)
```bash
# Set the same TEE policy hash for all services (SHA-256 hex of container/image/policy)
export TEE_POLICY_HASH=<64-char-hex>

python servers/ca_server.py
python servers/tlog_server.py
python servers/auth_server.py
python servers/coordinator_server.py
```

---

## Demo Flow
```bash
# Create a new signing session
python clients/cli.py request   --artifact-digest $(printf foo | shasum -a 256 | awk '{print $1}')

# Join session as participants (1 engineer + 2 stewards)
python clients/cli.py join --session <SESSION_ID> --name Alice --email alice@example.com
python clients/cli.py join --session <SESSION_ID> --name Bob   --email bob@example.com
python clients/cli.py join --session <SESSION_ID> --name Carol --email carol@example.com

# Verify transparency log entry
python clients/cli.py verify --artifact-digest <DIGEST>
```

---

## Running Inside OCI Confidential VMs
1. Launch **Confidential** AMD EPYC instances (SEV/SEV-SNP enabled).
2. Bake your container/venv into a **golden image** and compute:
   ```bash
   sha256sum <rootfs-or-container-digest>  # → TEE_POLICY_HASH
   ```
3. Export `TEE_POLICY_HASH` to all services and clients.
4. Ensure `/dev/sev-guest` is present and replace the `common/attestation_snp.py` stub with:
   - A real `SNP_GET_REPORT` ioctl call  
   - Verification against AMD’s root cert or a trusted verifier
5. Enable mTLS:
   ```bash
   export CA_TLS_CERT=...
   export CA_TLS_KEY=...
   ```
6. Deploy on a **private subnet**, open only required ports, and log to OCI Logging.

---


