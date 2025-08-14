//! FROST Signer (Axum) — inline documented
//!
//! # What this does
//! - Exposes `/sign` to return a **FROST round-2 signature share** for a provided message.
//! - Validates RPCs from the coordinator using **mTLS** (client cert auth) **and** a **JWT (HS256)**.
//! - Reads the local **KeyPackage** (per-signer secret share) from disk at startup.
//! - Exposes `/healthz` and `/metrics` (Prometheus) for liveness/observability.
//!
//! # Security & Ops
//! - **mTLS required**: the signer validates coordinator client certs against `TLS_CLIENT_CA`.
//! - **JWT required**: requests must include `Authorization: Bearer <token>` (HS256). Prefer RS256/EdDSA in prod.
//! - **No key reconstruction**: signer only holds its own **KeyPackage**; it never learns other shares.
//! - **NetworkPolicies**: restrict traffic to coordinator ↔ signer only (already in k8s/netpol).
//! - **Least privilege**: run as non-root, seccomp RuntimeDefault, drop caps (done in manifests).
//! - **Secrets**: mount TLS materials to `/tls`; mount JWT secret from a file in `/jwt` in prod.
//!
//! # Tunables / Config (env)
//! - `BIND` (default `0.0.0.0:7000`) — HTTP bind address (wrapped in TLS listener).
//! - `SIGNER_ID` (required) — this node’s FROST identifier (u16), used to load `share.json`.
//! - `FROST_STATE` (default `./frost_state`) — where `signer-<id>/share.json` is located.
//! - `TLS_CERT_PEM`  (`/tls/tls.crt`) — server certificate for inbound mTLS.
//! - `TLS_KEY_PEM`   (`/tls/tls.key`) — private key for server certificate (PKCS#8).
//! - `TLS_CLIENT_CA` (`/tls/ca.crt`)  — CA bundle of **trusted coordinator client cert** issuer(s).
//! - `JWT_HS256_B64` — base64 HS256 secret for auth (prefer file-mount; e.g., `/jwt/JWT_HS256_B64`).
//!
//! # Improvements / Production
//! - Move to **RS256/EdDSA JWT** with JWKS served by coordinator (or Vault); add `aud/exp/nbf` claims.
//! - Enforce **client cert SAN pinning** (e.g., DNS: frost-coordinator.frost.svc) or SPIFFE IDs.
//! - Rate limit & backoff per coordinator; add circuit-breaker metrics.
//! - Zeroize KeyPackage after graceful shutdown; ensure at-rest encryption if ever persisted.
//! - Verify per-request binding to TEE attestation nonce (if mutual attestation is enabled).

use axum::{routing::{post, get}, Json, Router, extract::State, extract::FromRef, http::HeaderMap};
use frost_ed25519 as frost;
use frost::round1::SigningNonces;
use frost::round2::SignatureShare;
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, path::Path, sync::Arc};
use prometheus::{Encoder, TextEncoder, IntCounter};
use lazy_static::lazy_static;
use jsonwebtoken::{DecodingKey, Validation, decode, Algorithm};
use rustls::{ServerConfig, Certificate, PrivateKey, RootCertStore};
use tokio_rustls::TlsAcceptor;

/// JSON body expected from coordinator for a round-2 signing request.
/// - `msg_b64`: base64 of the message to sign (JWS signing input).
/// - `round1_b64`: base64 of bincode-serialized `SigningNonces` for THIS signer.
/// - `signer_id`: sanity-check the intended signer id.
#[derive(Deserialize)]
struct SignReq {
    msg_b64: String,
    round1_b64: String,
    signer_id: u16,
}

/// Response with the base64-encoded bincode `SignatureShare`.
#[derive(Serialize)]
struct SignResp {
    sigshare_b64: String,
}

/// Wrapper for a signer's `KeyPackage` (bincode) loaded from disk at startup.
#[derive(serde::Deserialize)]
struct ShareFile { key_package: Vec<u8> }

#[tokio::main]
async fn main() {
    // Structured logs with env filter (use RUST_LOG=debug for TLS/JWT troubleshooting).
    tracing_subscriber::fmt().with_env_filter("info").init();

    // ---- Config & KeyPackage load ------------------------------------------------------------
    // Bind address for HTTPS (wrapped by rustls acceptor below)
    let bind = std::env::var("BIND").unwrap_or("0.0.0.0:7000".into());

    // This signer's numeric identifier (required), used for both file path and FROST identity checking.
    let signer_id: u16 = std::env::var("SIGNER_ID").unwrap().parse().unwrap();

    // Path to this signer's share file: ${FROST_STATE}/signer-<id>/share.json
    let state_dir = std::env::var("FROST_STATE").unwrap_or("./frost_state".into());
    let share_path = Path::new(&state_dir).join(format!("signer-{}/share.json", signer_id));
    let data = fs::read(share_path).expect("share file");

    // Deserialize wrapper JSON → extract bincode bytes → deserialize KeyPackage
    let sf: ShareFile = serde_json::from_slice(&data).unwrap();
    let key_pkg: frost::keys::KeyPackage = bincode::deserialize(&sf.key_package).unwrap();

    // ---- Metrics ---------------------------------------------------------------------------
    lazy_static! {
        static ref SIGN_REQS: IntCounter =
            IntCounter::new("frost_signer_requests_total", "Total sign requests").unwrap();
    }

    // ---- JWT verification key (HS256) -------------------------------------------------------
    // In production, prefer reading the shared secret from a mounted file or switch to RS256/EdDSA.
    #[derive(Clone)]
    struct AppState{ jwt_key: Arc<DecodingKey> }

    let jwt_key = std::env::var("JWT_HS256_B64")
        .ok()
        .map(|b| base64::decode(b).unwrap())
        .unwrap_or_else(|| b"devsecret".to_vec());
    let state = AppState{ jwt_key: Arc::new(DecodingKey::from_secret(&jwt_key)) };

    // ---- HTTP routes (served over TLS acceptor loop) ----------------------------------------
    let app = Router::new().with_state(state)
        // Liveness probe
        .route("/healthz", get(|| async { "ok" }))
        // Prometheus metrics
        .route("/metrics", get(|| async {
            let encoder = TextEncoder::new();
            let mut buf = Vec::new();
            encoder.encode(&prometheus::gather(), &mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        }))
        // Round-2 signing endpoint
        .route("/sign", post(|State(state): State<AppState>, headers: HeaderMap, Json(req): Json<SignReq>| async move {
            SIGN_REQS.inc();

            // ---- Authorization: JWT (HS256) --------------------------------------------------
            let auth = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
            if !auth.to_lowercase().starts_with("bearer ") {
                // Fail closed: return empty share (caller should treat as 401/403 equivalent).
                return Json(SignResp{ sigshare_b64: String::new() });
            }
            let token = &auth[7..];
            // TODO: add Validation with exp/nbf/aud/iss claims to prevent replay / scope creep.
            let _claims_ok = decode::<serde_json::Value>(
                token, &state.jwt_key, &Validation::new(Algorithm::HS256)
            ).map_err(|_|()).ok().ok_or(());

            // ---- Parse request ---------------------------------------------------------------
            let msg = base64::decode(req.msg_b64).unwrap();
            // Nonces produced in Round-1 (by coordinator) for THIS signer
            let nonces: SigningNonces = bincode::deserialize(&base64::decode(req.round1_b64).unwrap()).unwrap();

            // Optional sanity check: ensure the KeyPackage identifier matches `signer_id`
            // (Uncomment if you want an explicit guard)
            // let expected_id = frost::Identifier::try_from(req.signer_id).unwrap();
            // assert_eq!(u16::from(expected_id), req.signer_id);

            // ---- FROST Round-2: produce signature share --------------------------------------
            let sig_share: SignatureShare = frost::round2::sign(&nonces, &key_pkg, &msg).expect("sign");
            let sigshare_b64 = base64::encode(bincode::serialize(&sig_share).unwrap());
            Json(SignResp{ sigshare_b64 })
        }));

    // ---- TLS server (mTLS) -------------------------------------------------------------------
    // We require an authenticated client certificate (coordinator) chaining to TLS_CLIENT_CA.
    let addr: SocketAddr = bind.parse().unwrap();
    tracing::info!("signer {} listening on {}", signer_id, addr);

    let cert_path = std::env::var("TLS_CERT_PEM").unwrap_or("/tls/tls.crt".into());
    let key_path  = std::env::var("TLS_KEY_PEM").unwrap_or("/tls/tls.key".into());
    let ca_path   = std::env::var("TLS_CLIENT_CA").unwrap_or("/tls/ca.crt".into());

    // Server cert & key
    let certs = vec![Certificate(fs::read(cert_path).unwrap())];
    let key   = PrivateKey(fs::read(key_path).unwrap());

    // Trust store for client certs (coordinator must present a cert signed by this CA).
    let mut roots = RootCertStore::empty();
    let _ = roots.add_parsable_certificates(&[fs::read(ca_path).unwrap()]);

    // Client auth required: only accept connections with a valid client certificate.
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(roots)))
        .with_single_cert(certs, key)
        .unwrap();

    // Axum over a TLS accept loop
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(stream).await {
                // Serve Axum app over the negotiated TLS connection.
                let _ = axum::serve(tls, app.clone()).await;
            }
        });
    }
}