
# FROST Coordinator — Code Walkthrough & Operational Notes

This document explains the FROST **coordinator** service implemented with **Axum** (Rust) that aggregates threshold Ed25519 signatures using the `frost-ed25519` crate. It exposes health/metrics endpoints and a `/sign` RPC that orchestrates a t‑of‑n signing operation across signer nodes. It is hardened with **mTLS** and **JWT** auth for RPCs to the signers.

> File: `frost/coordinator/src/main.rs`

---

## High‑level responsibilities

- Load the **group public key package** from persisted state (`FROST_STATE/group.json`).
- Accept sign requests (`/sign`) with a base64url message and desired participants.
- Drive **FROST Round 1** (nonces/commitments) client‑side for the chosen participant set.
- Request **FROST Round 2** signature shares from the selected signers over **mTLS** with **Bearer JWT**.
- Aggregate signature shares into a standard **Ed25519** signature and return it (base64).
- Expose **/healthz** and **/metrics** (Prometheus text format).

---

## Endpoint contract

### `GET /healthz`
- Liveness/readiness probe.
- Returns `200 OK` with `ok`.

### `GET /metrics`
- Prometheus metrics including:
  - `frost_coordinator_signs_total` — count of successful aggregate sign operations.

### `POST /sign`
Request body (`application/json`):
```json
{
  "msg_b64": "<base64 of JWS signing input>",
  "participants": [1,2,3],
  "signer_urls": ["https://frost-signer-1.frost.svc:7000", "https://frost-signer-2.frost.svc:7000", "https://frost-signer-3.frost.svc:7000"]
}
```

Response:
```json
{
  "signature_b64": "<base64 Ed25519 signature>",
  "group_public_b64": "<base64 group Ed25519 public key>"
}
```

---

## Request flow (important lines)

1. **Load group public key package**
   ```rust
   let state_dir = std::env::var("FROST_STATE").unwrap_or("./frost_state".into());
   let group_path = Path::new(&state_dir).join("group.json");
   let gf: GroupFile = serde_json::from_slice(&fs::read(group_path)? )?;
   let pubpkg: PublicKeyPackage = bincode::deserialize(&gf.public_key_package)?;
   ```

2. **mTLS client config** for outbound signer calls
   ```rust
   let cert_pem = var("TLS_CERT_PEM").unwrap_or("/tls/tls.crt".into());
   let key_pem  = var("TLS_KEY_PEM").unwrap_or("/tls/tls.key".into());
   let ca_pem   = var("TLS_SERVER_CA").unwrap_or("/tls/ca.crt".into());
   // Root CA + client auth cert/key -> reqwest Client with preconfigured TLS
   ```

3. **JWT (HS256) for RPC authorization**
   ```rust
   let jwt_key = var("JWT_HS256_B64").map(base64::decode).unwrap_or(b"devsecret".to_vec());
   let enc_key = EncodingKey::from_secret(&jwt_key);
   let token   = jsonwebtoken::encode(&Header::default(), &json!({"iss":"frost-coord"}), &enc_key)?;
   // sent as Authorization: Bearer <token> to each signer
   ```

4. **FROST rounds**
   ```rust
   // Round 1: per-participant nonces/commitments
   let (nonces, commitments) = round1::commit(&mut rng, identifier);

   // Round 2: collect signature shares from each signer
   let sigshare: round2::SignatureShare = bincode::deserialize(...)?;

   // Aggregate final signature
   let sig = round2::aggregate(&msg, &sigshares, &commitments_map, &pubpkg)?;
   ```

5. **Metrics**
   ```rust
   lazy_static! { static ref SIGNS_TOTAL: IntCounter = IntCounter::new("frost_coordinator_signs_total", "Aggregated sign operations").unwrap(); }
   SIGNS_TOTAL.inc();
   ```

---

## Security & Ops

### Channel security
- **mTLS** is required for outbound RPCs (coordinator → signer). The coordinator loads a **client certificate** and validates the **signer server certificate** against `TLS_SERVER_CA`.
- Each request also includes a **JWT** (`Authorization: Bearer ...`) signed with **HS256** for signer‑side authorization.

**Operational guidance**
- Certs/keys are expected from a *short‑lived* source (e.g., cert‑manager `Certificate` mounting `/tls`). Rotate automatically.
- Prefer **private networking** (ClusterIP/headless Service) and a **NetworkPolicy** that only allows **coordinator ↔ signer** traffic.
- The JWT secret should come from a **file‑mounted secret** (e.g., `/jwt/JWT_HS256_B64`), not an env var, and originate from **OCI Vault** via an external‑secrets controller.

### Supply‑chain / provenance
- Pin the container image by **digest** in Kubernetes manifests.
- Enable **seccomp: RuntimeDefault**, **runAsNonRoot**, drop **ALL** Linux capabilities.
- Keep the coordinator’s `/metrics` endpoint internal only (scraped by Prometheus on the cluster network).

### Logging & audit
- Every successful `/sign` increments `frost_coordinator_signs_total`. Add request IDs and signer IDs to the append‑only audit log in the mint API layer for full traceability (already implemented there).

### Failure domains
- The coordinator is stateless and can be replicated (single leader or idempotent calls). Signers run as **DaemonSets** across ADs for t‑of‑n availability.

---

## Tunables / Config

| Env Var             | Default              | Purpose |
|---------------------|----------------------|---------|
| `BIND`              | `0.0.0.0:7100`       | Listening address for the coordinator HTTP server. |
| `FROST_STATE`       | `./frost_state`      | Directory containing `group.json` for the group public key package. |
| `TLS_CERT_PEM`      | `/tls/tls.crt`       | Client certificate for mTLS to signers. |
| `TLS_KEY_PEM`       | `/tls/tls.key`       | Private key for the client certificate. |
| `TLS_SERVER_CA`     | `/tls/ca.crt`        | Root CA bundle to validate signer server certs. |
| `JWT_HS256_B64`     | *(none; dev fallback)* | Base64‑encoded HS256 secret for signer RPC auth. Prefer **`JWT_HS256_B64_FILE`** via mounted secret. |
| `RUST_LOG`          | `info`               | Adjust Axum/tracing log level. |

**Kubernetes**
- Mount `/tls` from `cert-manager` `Certificate` (`frost-tls`) and `/jwt` from a secret sourced by **OCI Vault**.
- Use headless `Service` for signers and pass their **cluster DNS** names in `signer_urls` (or discover via endpoints).

---

## Improvements (future work)

- **JWT RS256/EdDSA**: Move from HS256 to **RS256/EdDSA** and rotate keys via **OCI Vault**. Signers verify against a JWKS set (or mounted public key) — this eliminates shared symmetric material.
- **Mutual attestation**: Carry TEE attestation evidence end‑to‑end (API → coordinator → signers), bind the FROST request to an enclave report nonce, and enforce measurement/policy pinning per hop.
- **Rate limiting & backoff** on outbound RPCs to each signer and **hedged requests** for quicker quorum under partial outage.
- **mTLS name constraints**: Enforce SAN pinning (`DNS: frost-signer.frost.svc`) or SPIFFE IDs if a mesh is in use.
- **Nonces/commitments service**: Pre‑compute Round 1 nonces/commitments per signer epoch to reduce per‑request latency.
- **Observability**: add histograms for request latency, error counters per signer, and a circuit‑breaker state metric.

---

## Getting to Production

1. **Keying & Auth**
   - Replace **HS256** with **RS256/EdDSA** JWTs, keys sourced from **OCI Vault**, with rotation and audience/issuer claims enforced at the signer.
   - Per‑signer **client cert** identities with short lifetimes and **NetworkPolicies** locked to the coordinator namespace only.

2. **Resilience**
   - Run multiple coordinator replicas behind a ClusterIP/VirtualService and design idempotent `/sign` usage (client retries safe).
   - Add **timeout budgets** and **quorum selection** strategies (e.g., pick t signers from different ADs).

3. **Compliance**
   - Log signer IDs, participant sets, and token correlation IDs to an **append‑only audit log** with **WORM** retention (OCI Logging + Object Storage).
   - Prove **no key reconstruction**: only Ed25519 signatures are emitted; secret material never leaves signer memory.

4. **Performance**
   - Pre‑warm connections with **HTTP/2** and keep‑alive. Benchmark Round 1/2 batching and evaluate CPU pinning and NUMA locality on signer hosts.

---

## Example usage

**Request**
```bash
curl -sS -X POST https://frost-coordinator.frost.svc:7100/sign \
  --cacert /tls/ca.crt --cert /tls/tls.crt --key /tls/tls.key \
  -H "Authorization: Bearer $(printf '%s' "$JWT" )" \  -H 'content-type: application/json' \  -d '{"msg_b64":"<base64>","participants":[1,2],"signer_urls":["https://frost-signer-1.frost.svc:7000","https://frost-signer-2.frost.svc:7000"]}'
```

**Response**
```json
{"signature_b64":"<base64>","group_public_b64":"<base64>"}
```

---

## Notes

- The coordinator never holds private key **shares**. It only generates nonces/commitments, collects signature **shares**, and aggregates the final signature per the FROST protocol.
- The Ed25519 signature returned is a **standard** signature that can be verified by any Ed25519 verifier using the group public key.
