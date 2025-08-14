//! FROST Keygen (dealer-style) — inline documented
//!
//! # What this does
//! - Generates a t-of-n **FROST Ed25519** key set using a **dealer** (this binary).
//! - Emits a **group public key package** and **per-signer secret shares** to disk.
//!
//! # Outputs (on disk)
//! - `${FROST_OUT}/group.json` — JSON with a bincode-serialized `PublicKeyPackage`.
//! - `${FROST_OUT}/signer-<id>/share.json` — JSON with a bincode-serialized `KeyPackage` per signer.
//!
//! # Security & Ops
//! - **Dealer model**: This binary learns/handles *all* shares during generation.
//!   - OK for PoC/bootstrap; **not acceptable** for production. Use **DKG** (distributed key generation)
//!     so no single host ever holds all shares.
//! - **File permissions**: shares are highly sensitive. Ensure directory modes are restrictive (e.g. 0700).
//!   In Kubernetes/OKE, prefer sealed/ephemeral volumes and immediate distribution to signer pods/hosts.
//! - **Provenance**: Record who ran keygen, when, version, and inputs (t, n) in your audit trail.
//!
//! # Tunables / Config (env)
//! - `FROST_N`   (default `"3"`) — total number of signers (n).
//! - `FROST_T`   (default `"2"`) — threshold (t) signers needed to sign.
//! - `FROST_OUT` (default `"./frost_state"`) — output directory for group/share files.
//!
//! # Improvements / Production
//! - Replace with **FROST DKG** so that shares are generated *at* signers; the coordinator never sees them.
//! - Encrypt shares at rest per signer (KMS envelope) until loaded in-memory by signers.
//! - Add checksum/manifests (e.g. SHA-256) with signatures (Sigstore) for artifacts integrity.
//! - Add zeroization (e.g. `zeroize` crate) for in-memory key material after write.
//! - Run inside a TEE (e.g., OCI CVM SEV-SNP) and bind outputs to attestation for provenance.

use frost_ed25519 as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Serialize, Deserialize};
use std::{fs, path::Path};

/// JSON wrapper for a single signer's secret `KeyPackage` (bincode inside).
#[derive(Serialize, Deserialize)]
struct ShareFile { key_package: Vec<u8> }

/// JSON wrapper for the group's `PublicKeyPackage` (bincode inside).
#[derive(Serialize, Deserialize)]
struct GroupFile { public_key_package: Vec<u8> }

fn main(){
    // ---- Parameters (t, n, out path) ---------------------------------------------------------
    let n: u16 = std::env::var("FROST_N").unwrap_or("3".into()).parse().unwrap();
    let t: u16 = std::env::var("FROST_T").unwrap_or("2".into()).parse().unwrap();
    let out = std::env::var("FROST_OUT").unwrap_or("./frost_state".into());

    // Ensure output directory exists; you may want to chmod 0700 here for stricter perms.
    fs::create_dir_all(&out).unwrap();

    // ---- Dealer-style key generation ---------------------------------------------------------
    // NOTE: Dealer learns all shares — PoC only. Switch to DKG for production.
    let mut rng = ChaCha20Rng::from_entropy();
    let (shares, pubpkg): (std::collections::BTreeMap<frost::Identifier, KeyPackage>, PublicKeyPackage) =
        frost::keys::generate_with_dealer(t, n, &mut rng).expect("keygen");

    // ---- Write group public package ----------------------------------------------------------
    let group_path = Path::new(&out).join("group.json");
    let group = GroupFile {
        public_key_package: bincode::serialize(&pubpkg).unwrap()
    };
    fs::write(
        &group_path,
        serde_json::to_vec_pretty(&group).unwrap()
    ).unwrap();
    println!("Wrote group public key package to {}", group_path.display());

    // ---- Write each per-signer share ---------------------------------------------------------
    // Directory layout:
    //   ${FROST_OUT}/signer-<id>/share.json
    for (id, kp) in shares {
        let share_dir = Path::new(&out).join(format!("signer-{}", u16::from(id)));
        fs::create_dir_all(&share_dir).unwrap();

        let path = share_dir.join("share.json");
        let sf = ShareFile { key_package: bincode::serialize(&kp).unwrap() };

        // In production, consider:
        //  - encrypting the serialized payload with per-signer KEK (OCI KMS),
        //  - atomic write + fsync, then shred or zeroize intermediates.
        fs::write(&path, serde_json::to_vec_pretty(&sf).unwrap()).unwrap();

        println!("Wrote signer share for id {} to {}", u16::from(id), path.display());
    }

    // Optional: Zeroize in-memory copies here (requires `zeroize` and struct support).
    // drop(rng);  // RNG will be dropped automatically.
}