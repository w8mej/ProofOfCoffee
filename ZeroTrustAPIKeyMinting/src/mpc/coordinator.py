"""
mpc/coordinator.py — MPC Ed25519 Key Reconstruction & Signing (Documented)

Purpose
-------
Coordinates **threshold-based signing** using Multi-Party Computation (MPC) shares
to reconstruct an Ed25519 key from a distributed seed, then signs arbitrary messages.
Also supports a **hybrid signing** workflow combining local MPC signing with a
cloud Hardware Security Module (HSM) signature (e.g., Oracle Cloud Infrastructure Vault).

Key Concepts
------------
- MPC shares: Integers representing secret shares of a seed, generated via Shamir's Secret Sharing
  or equivalent. A quorum of shares is required to recover the original 32-byte seed.
- Deterministic key derivation: Seed → HKDF (info="mpc-ed25519-poc") → Ed25519 private key.
- Hybrid signing: Combine signatures from multiple trust domains (local MPC & OCI HSM).

Security & Ops Notes
--------------------
- Threshold signing: The private key never exists in full outside the MPC recovery function,
  except in ephemeral memory during signing.
- Key Derivation:
  • HKDF-SHA256 with fixed `info` ensures deterministic but domain-separated key material.
  • No salt is used here for reproducibility; in production, use a salt derived from
    deployment-specific entropy to harden against related-seed attacks.
- Hybrid mode:
  • Produces two independent signatures over the same message.
  • Downstream verifiers may require both signatures to consider an operation valid.

Production Considerations
-------------------------
- Zeroization: Securely wipe reconstructed private key bytes after signing.
- Policy enforcement: Hybrid signatures should be policy-gated (e.g., both local & HSM must sign).
- Signature format: This PoC uses `.hex()` for transport. In production, use raw bytes or
  base64url-encoded for compactness.
"""

from .oci_hsm import oci_hsm_sign
from dataclasses import dataclass
from typing import List, Tuple

from .shares import recover_secret
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --- Data Structures ----------------------------------------------------------------------------

@dataclass
class MPCKey:
    """
    Represents a reconstructed Ed25519 key from MPC shares.

    Attributes:
      private_key: Ed25519PrivateKey instance.
      public_key_pem: PEM-encoded public key bytes.
      kid: Key identifier (string), used in JWTs or approval metadata.
    """
    private_key: ed25519.Ed25519PrivateKey
    public_key_pem: bytes
    kid: str


# --- Key Derivation ------------------------------------------------------------------------------

def derive_ed25519_from_seed(seed_int: int, kid: str) -> MPCKey:
    """
    Deterministically derive an Ed25519 keypair from a 256-bit integer seed.

    Steps:
      1. Convert integer seed → 32-byte big-endian representation.
      2. HKDF-SHA256 (length=32, info="mpc-ed25519-poc") to derive uniform key material.
      3. Instantiate Ed25519PrivateKey from HKDF output.
      4. Export public key in PEM format.

    Args:
      seed_int: 256-bit seed as an integer.
      kid: Key identifier string.

    Returns:
      MPCKey with private key, PEM public key, and KID.
    """
    seed_bytes = seed_int.to_bytes(32, "big", signed=False)
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # reproducible derivation; supply salt in production
        info=b"mpc-ed25519-poc"
    ).derive(seed_bytes)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(okm)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return MPCKey(private_key=priv, public_key_pem=pub_pem, kid=kid)


# --- Signing -------------------------------------------------------------------------------------

def reconstruct_and_sign(shares: List[Tuple[int, int]], kid: str, msg: bytes) -> bytes:
    """
    Reconstruct the MPC seed from shares and sign a message.

    Args:
      shares: List of (index, share_value) tuples from MPC participants.
      kid: Key identifier string.
      msg: Message bytes to sign.

    Returns:
      Ed25519 signature bytes over `msg`.
    """
    seed = recover_secret(shares)
    key = derive_ed25519_from_seed(seed, kid)
    return key.private_key.sign(msg)


# --- OCI HSM Integration -------------------------------------------------------------------------


def hybrid_sign_with_hsm(shares, kid: str, msg: bytes, vault_key_ocid: str) -> dict:
    """
    Produce both an MPC Ed25519 signature and an OCI HSM signature over the same message.

    Workflow:
      1. Locally reconstruct Ed25519 key from MPC shares → sign `msg`.
      2. Request HSM signature from OCI Vault key (vault_key_ocid) over `msg`.
      3. Return both signatures in hex-encoded format.

    Args:
      shares: MPC shares for reconstructing the local Ed25519 key.
      kid: Key identifier string for local key.
      msg: Message bytes to sign.
      vault_key_ocid: OCI Vault Key OCID for HSM signing.

    Returns:
      dict: {
        "local_sig": "<hex string>",
        "hsm_sig": "<hex string>"
      }
    """
    local_sig = reconstruct_and_sign(shares, kid, msg)
    hsm_sig = oci_hsm_sign(vault_key_ocid, msg)
    return {
        "local_sig": local_sig.hex(),
        "hsm_sig": hsm_sig.hex()
    }
