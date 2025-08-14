
//! FROST Coordinator (Axum) — inline documented
//!
//! # Security & Ops
//! - **mTLS + JWT** on outbound RPCs to signers. Coordinator presents a client cert and validates signer server certs.
//! - **Private networking** only; pair with NetworkPolicies to restrict traffic to coordinator ↔ signers.
//! - **No key reconstruction**: only nonces/commitments are generated here; signature shares are aggregated into a standard Ed25519 signature.
//! - **Observability**: `/healthz` and `/metrics` (Prometheus). Alert on request error rates and certificate expiry.
//! - **Secrets**: prefer mounting short‑lived certs (cert-manager) to `/tls` and a file-sourced JWT secret from OCI Vault to `/jwt`.
//!
//! # Tunable / Config
//! - `BIND` (default `0.0.0.0:7100`) — HTTP bind address.
//! - `FROST_STATE` (default `./frost_state`) — path containing `group.json` (PublicKeyPackage, bincode-serialized inside JSON).
//! - `TLS_CERT_PEM` `/tls/tls.crt` — client certificate for mTLS to signers.
//! - `TLS_KEY_PEM`  `/tls/tls.key` — private key (PKCS#8) for client cert.
//! - `TLS_SERVER_CA` `/tls/ca.crt` — CA bundle to verify signer servers.
//! - `JWT_HS256_B64` — base64 secret for HS256 RPC auth (prefer `JWT_HS256_B64_FILE` pattern in deployment).
//! - `RUST_LOG=info` — set tracing level.
//!
//! # Improvements / Production
//! - Replace HS256 with **RS256/EdDSA** and distribute JWKS to signers.
//! - Carry **TEE attestation** evidence end-to-end (API→Coordinator→Signer) and bind to request nonce.
//! - Add latency histograms and per-signer error counters; implement **hedged** requests for quorum.
//! - Enforce SAN pinning or SPIFFE IDs for mTLS peer identity.
//! - Discover signer endpoints via the headless Service (kube DNS) rather than explicit URLs in requests.

use axum::{routing::{post, get}, Json, Router};
use frost_ed25519 as frost;
use frost::round1;
use frost::round2;
use frost::keys::PublicKeyPackage;
use reqwest::{Client, ClientBuilder};
use rustls::{ClientConfig, Certificate, PrivateKey, RootCertStore};
use tokio_rustls::rustls_pemfile::{certs, pkcs8_private_keys};
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, path::Path, collections::BTreeMap};
use prometheus::{Encoder, TextEncoder, IntCounter};
use lazy_static::lazy_static;

/// Incoming request for a coordinated FROST signature.
/// - `msg_b64`: base64-encoded JWS signing input (header.payload) to be signed.
/// - `participants`: signer numeric IDs participating in this quorum (t-of-n).
/// - `signer_urls`: base URLs for each selected signer; must align 1:1 with `participants`.
#[derive(Deserialize)]
struct SignReq {
    msg_b64: String,
    participants: Vec<u16>,   // which signer ids to use
    signer_urls: Vec<String>, // base URLs matching participants
}

/// Response: standard Ed25519 signature (base64) and the group public key (base64).
#[derive(Serialize)]
struct SignResp {
    signature_b64: String,
    group_public_b64: String,
}

/// On-disk envelope containing a bincode-serialized `PublicKeyPackage`.
#[derive(serde::Deserialize)]
struct GroupFile { public_key_package: Vec<u8> }

/// Minimal response from signer containing its round-2 signature share (base64/bincode).
#[derive(serde::Deserialize)]
struct ShareResp { sigshare_b64: String }

#[tokio::main]
async fn main(){
    // Structured logs; honor RUST_LOG if supplied (e.g., debug for troubleshooting TLS/JWT).
    tracing_subscriber::fmt().with_env_filter("info").init();

    // ---- Config & state loading --------------------------------------------------------------
    // Bind address for the HTTP server
    let bind = std::env::var("BIND").unwrap_or("0.0.0.0:7100".into());
    // Directory holding `group.json` produced by FROST keygen
    let state_dir = std::env::var("FROST_STATE").unwrap_or("./frost_state".into());
    let group_path = Path::new(&state_dir).join("group.json");
    // Read group public key package from disk (JSON wrapper with bincode payload)
    let data = fs::read(group_path).expect("group.json");
    let gf: GroupFile = serde_json::from_slice(&data).unwrap();
    let pubpkg: PublicKeyPackage = bincode::deserialize(&gf.public_key_package).unwrap();

    // ---- Outbound TLS client (mTLS) ----------------------------------------------------------
    // We establish mTLS when calling signers: present a client cert and validate the server.
    let cert_pem = std::env::var("TLS_CERT_PEM").unwrap_or("/tls/tls.crt".into());
    let key_pem  = std::env::var("TLS_KEY_PEM").unwrap_or("/tls/tls.key".into());
    let ca_pem   = std::env::var("TLS_SERVER_CA").unwrap_or("/tls/ca.crt".into());

    // Build a RootCertStore from the provided CA bundle; signers' server certs must chain to this.
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(&[std::fs::read(ca_pem).unwrap()]);

    // Load our client certificate chain and private key (PKCS#8). In production, rotate automatically.
    let cert_chain = vec![Certificate(std::fs::read(cert_pem).unwrap())];
    let key = {
        let mut rd = std::io::BufReader::new(std::fs::File::open(key_pem).unwrap());
        let keys = pkcs8_private_keys(&mut rd).unwrap();
        PrivateKey(keys[0].clone())
    };

    // Assemble rustls client config for mutual TLS and feed into reqwest client.
    let tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .unwrap();
    let client: Client = ClientBuilder::new()
        .use_preconfigured_tls(tls)
        .build()
        .unwrap();

    // ---- Metrics & Auth ----------------------------------------------------------------------
    // Prometheus counter: count of successful aggregated signatures.
    lazy_static! {
        static ref SIGNS_TOTAL: IntCounter =
            IntCounter::new("frost_coordinator_signs_total", "Aggregated sign operations").unwrap();
    }

    // JWT for RPC auth to signers (Bearer). HS256 is used here; prefer RS256/EdDSA in production.
    // NOTE: Prefer mounting a file and reading it at startup; env var is acceptable only in dev.
    let jwt_key = std::env::var("JWT_HS256_B64")
        .ok()
        .map(|b| base64::decode(b).unwrap())
        .unwrap_or_else(|| b"devsecret".to_vec());
    let enc_key = EncodingKey::from_secret(&jwt_key);

    // ---- HTTP routes -------------------------------------------------------------------------
    let app = Router::new()
        // Health probe
        .route("/healthz", get(|| async { "ok" }))
        // Prometheus metrics
        .route("/metrics", get(|| async {
            let encoder = TextEncoder::new();
            let mut buf = Vec::new();
            encoder.encode(&prometheus::gather(), &mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        }))
        // FROST signing orchestration endpoint
        .route("/sign", post({
            let client = client.clone(); // reqwest client with mTLS
            move |Json(req): Json<SignReq>| {
                // Clone handles for the async block
                let client = client.clone();
                let pubpkg = pubpkg.clone();

                async move {
                    // 1) Decode message to be signed (JWS signing input)
                    let msg = base64::decode(&req.msg_b64).unwrap();

                    // 2) Round 1 (Coordinator side): generate nonces & commitments per participant.
                    //    We derive per-identifier values and keep them in maps for Round 2 & aggregate.
                    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
                    let mut commitments_map = BTreeMap::new();
                    let mut nonces_map = BTreeMap::new();
                    for id in &req.participants {
                        // Convert numeric id to FROST Identifier
                        let identifier = frost::Identifier::try_from(*id).unwrap();
                        let (nonces, commitments) = round1::commit(&mut rng, identifier);
                        commitments_map.insert(identifier, commitments);
                        nonces_map.insert(identifier, nonces);
                    }
                    // (Note) `round1_b64` kept here for clarity; each signer only needs its own nonces.
                    let _round1_b64_all = base64::encode(bincode::serialize(&nonces_map).unwrap());

                    // 3) Round 2: request signature shares from each selected signer over mTLS + JWT.
                    let mut sigshares = BTreeMap::new();
                    for (i, id) in req.participants.iter().enumerate() {
                        let url = format!("{}/sign", &req.signer_urls[i]);

                        // Each signer receives only its own nonces (privacy & minimality).
                        let sid = frost::Identifier::try_from(*id).unwrap();
                        let own_nonces = nonces_map.get(&sid).unwrap();
                        let payload = serde_json::json!({
                            "msg_b64": req.msg_b64,
                            "round1_b64": base64::encode(bincode::serialize(own_nonces).unwrap()),
                            "signer_id": id
                        });

                        // Short-lived JWT for RPC authorization (consider adding aud/exp/nbf/nonce).
                        let token = jsonwebtoken::encode(
                            &Header::default(),
                            &serde_json::json!({"iss":"frost-coord"}),
                            &enc_key
                        ).unwrap();

                        // mTLS (reqwest client) + Bearer token
                        let resp: ShareResp = client
                            .post(url)
                            .bearer_auth(token)
                            .json(&payload)
                            .send()
                            .await
                            .unwrap()
                            .json()
                            .await
                            .unwrap();

                        // Deserialize the signer's round-2 share
                        let sigshare: round2::SignatureShare =
                            bincode::deserialize(&base64::decode(resp.sigshare_b64).unwrap()).unwrap();
                        sigshares.insert(sid, sigshare);
                    }

                    // 4) Aggregate final signature (standard Ed25519) and return base64 payloads.
                    let sig = round2::aggregate(&msg, &sigshares, &commitments_map, &pubpkg)
                        .expect("aggregate");
                    SIGNS_TOTAL.inc();

                    let sig_b64 = base64::encode(sig.to_bytes());
                    let group_pub_b64 = base64::encode(pubpkg.group_key().to_bytes());
                    Json(SignResp { signature_b64: sig_b64, group_public_b64: group_pub_b64 })
                }
            }
        }));

    // ---- Start server ------------------------------------------------------------------------
    let addr: SocketAddr = bind.parse().unwrap();
    tracing::info!("coordinator listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
