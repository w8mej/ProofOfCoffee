# MPC Ephemeral Signing — Python gRPC + Protobuf POC (TEE-attested)

This variant adds **TEE attestation (AMD SEV-SNP)** and optional **mTLS** so every RPC
is served only if the caller proves it runs in an approved OCI Confidential VM.

> ⚠️ Crypto note: Threshold signing remains a POC (approval quorum + Ed25519).
> Swap `common/` with a real MPC/FROST engine for production.

## What’s new
- **TEE attestation on every RPC** via gRPC metadata (nonce + evidence + policy hash).
- **Server interceptors** verify evidence before passing calls to handlers.
- **Client interceptors** attach evidence automatically.
- **Optional mTLS** for all channels (in addition to attestation).

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m grpc_tools.protoc -I proto proto/mpc.proto --python_out=gen --grpc_python_out=gen
```

## Run services (four terminals)
```bash
# set the same TEE policy hash on all services (hex string representing image/policy)
export TEE_POLICY_HASH=<64-hex-sha256-of-your-policy>

python servers/ca_server.py
python servers/tlog_server.py
python servers/auth_server.py
python servers/coordinator_server.py
```

## Demo flow
```bash
# new session
python clients/cli.py request --artifact-digest $(printf foo | shasum -a 256 | awk '{print $1}')

# join 3 times from separate shells (1 engineer + 2 stewards)
python clients/cli.py join --session <SESSION_ID> --name Alice --email alice@ex.com
python clients/cli.py join --session <SESSION_ID> --name Bob   --email bob@ex.com
python clients/cli.py join --session <SESSION_ID> --name Carol --email carol@ex.com

# verify transparency log
python clients/cli.py verify --artifact-digest <DIGEST>
```

## Running on **OCI Confidential VMs**
1. Launch **Confidential** AMD EPYC instances (SEV/SEV-SNP enabled).
2. Bake a **golden image** (container/venv) and compute `TEE_POLICY_HASH` (e.g., SHA-256 of the image rootfs or signed container digest). Export it on all nodes.
3. Ensure the guest exposes `/dev/sev-guest` (SNP). Replace the fallback in
   `common/attestation_snp.py` with a real `SNP_GET_REPORT` ioctl and verification
   (or call a central Verifier). Bind a **fresh nonce** + `TEE_POLICY_HASH` when requesting the report.
4. Enable **mTLS**:
   - Servers: set `*_TLS_CERT` and `*_TLS_KEY` env vars to PEM files.
   - CLI/clients: set `CLIENT_TLS_CA`, `CLIENT_TLS_CERT`, `CLIENT_TLS_KEY`.
5. Network: deploy on a private subnet; allow only required ports. Enable logging to OCI Logging.

## Security & Operations notes
- **Defense in depth**: mTLS authenticates *who*, SNP attestation proves *where/how*.
- **Replay protection**: Nonce is bound in the attestation report_data.
- **Policy pinning**: Requests fail if `TEE_POLICY_HASH` doesn’t match.
- **Auditing**: Add interceptors to emit user/session/method/attestation-digest.
- **Secrets**: Store certs/keys and policy in **OCI Vault**; rotate regularly.

## Tunables
- `TEE_POLICY_HASH` (hex) — required for both client and server interceptors.
- Coordinator: `REQUIRED_ENGINEERS`, `REQUIRED_STEWARDS`, `COORD_BIND`, `COORD_THREADS`, `COORD_TLS_CERT/KEY`
- CA: `CA_BIND`, `CA_THREADS`, `CA_TTL_SECONDS`, `CA_TLS_CERT/KEY`
- TLog: `TLOG_BIND`, `TLOG_THREADS`, `TLOG_TLS_CERT/KEY`
- Auth: `AUTH_BIND`, `AUTH_THREADS`, `AUTH_TLS_CERT/KEY`, `AUTH_DEMO_TOKEN`
- Client: `CLIENT_TLS_CA`, `CLIENT_TLS_CERT`, `CLIENT_TLS_KEY`, `COORDINATOR_ADDR`, `TLOG_ADDR`

## Swap in real MPC/FROST
Keep this API and replace `common/mpc_provider.py` with a provider that runs DKG,
stores hardware-wrapped shares, and emits true threshold partials for aggregation.
