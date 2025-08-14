"""
mpc/approvals.py — Approval payload hashing, PKCS#11-based signing (documented)

Purpose
-------
Implements a minimal **approval-signing subsystem** for multi-party or policy-gated
token minting. Each approval is a signed hash of a deterministic "challenge payload"
(user, scopes, ttl, nonce, timestamp). The design supports YubiKey PIV-backed keys
via PKCS#11 (e.g., OpenSC's `opensc-pkcs11.so`).

Workflow
--------
1. `challenge_payload(...)` → JSON bytes (stable key order, minified) containing:
      user, scopes, ttl, nonce, ts=epoch seconds.
   This ensures a reproducible, canonical representation for hashing.

2. `hash_approval(...)` → SHA-256 digest of the challenge payload.

3. `PKCS11Signer.sign(...)` → ECDSA-P256/SHA256 signature over the digest,
   using a PKCS#11-compatible token slot (tested with YubiKey PIV slot 9a).

4. `package_approvals(...)` → wraps {key_id: raw_signature_bytes} into a list
   of `Approval` dataclasses with base64-encoded signatures for transport.

Security & Ops Notes
--------------------
- PIV / PKCS#11:
  • Intended for **attestation of approval**, *not* JWT signing. Use a separate Ed25519
    key for token issuance.
  • PKCS#11 label lookup: uses `Attribute.LABEL`. If multiple tokens are present, adjust
    `slot` index.

- Canonicalization:
  • Challenge payload uses `sort_keys=True` to ensure consistent hashing across signers.

- Transport:
  • Approvals are packaged with `key_id` and `signer` (here identical) to support
    policy engines that match signatures to authorized approvers.

Production Considerations
-------------------------
- Signature verification:
  • This PoC does not perform ECDSA verification — `verify_approval` is a stub.
    In production, load the P-256 public key and use `cryptography.hazmat.primitives.asymmetric.ec`
    to verify the DER-encoded signature bytes against the digest.

- Anti-replay:
  • Nonce should be random and unique per mint attempt; TTL should be short (e.g., < 5 min).
  • Backend must reject reused `(nonce, signer)` tuples.

- Audit:
  • Log `key_id`, `scopes`, `ttl`, `nonce`, `ts` for each approval received.
  • Optionally, include certificate fingerprint in the Approval for traceability.

Environment Variables
---------------------
PKCS11_LIB       → path to PKCS#11 provider library (e.g., /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so)
PKCS11_PIN       → PIV user PIN (string)
PKCS11_KEY_LABEL → label of private key object to use (string)
"""

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import List, Dict

# Optional PKCS#11 import (OpenSC/YubiKey PIV)
try:
    import pkcs11
    from pkcs11 import Attribute, ObjectClass, Mechanism
except Exception:
    pkcs11 = None


@dataclass
class Approval:
    """Represents one approval signature by a specific key/signer."""
    key_id: str         # Logical key identifier (e.g., certificate fingerprint)
    signer: str         # Human-readable signer identity; often same as key_id
    signature_b64: str  # Base64-encoded signature bytes


# --- Payload construction and hashing -----------------------------------------------------------

def challenge_payload(user: str, scopes: List[str], ttl: int, nonce: str) -> bytes:
    """
    Build a canonical challenge payload to be signed for approval.

    Args:
      user: Username or unique identity string.
      scopes: List of scopes requested (exact match to what will be minted).
      ttl: Requested token lifetime in seconds.
      nonce: Unique, random string for anti-replay.

    Returns:
      Canonical JSON bytes with sorted keys:
        {"nonce": "...", "scopes": [...], "ts": <epoch>, "ttl": <seconds>, "user": "..."}
    """
    doc = {
        "user": user,
        "scopes": scopes,
        "ttl": ttl,
        "nonce": nonce,
        "ts": int(time.time()),
    }
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")


def hash_approval(doc: bytes) -> bytes:
    """
    Compute the SHA-256 digest of a challenge payload.

    Args:
      doc: Canonical challenge payload bytes from `challenge_payload`.

    Returns:
      32-byte SHA-256 digest.
    """
    return hashlib.sha256(doc).digest()


# --- PKCS#11 signer -----------------------------------------------------------------------------

class PKCS11Signer:
    """
    Sign approval digests using a PKCS#11-backed private key (e.g., YubiKey PIV slot 9a).

    Environment setup:
      PKCS11_LIB       = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
      PKCS11_PIN       = 123456            # PIV user PIN
      PKCS11_KEY_LABEL = authkey           # key label or ID in token

    Notes:
      • Mechanism: ECDSA with SHA-256 (P-256 key).
      • This is *not* used for JWT signing — it’s a distinct attestation key.
    """

    def __init__(self, library_path: str, pin: str, key_label: str, slot: int = 0):
        if pkcs11 is None:
            raise RuntimeError(
                "python-pkcs11 not available — install via pip.")
        self.lib = pkcs11.lib(library_path)
        self.pin = pin
        self.key_label = key_label
        self.slot = slot

    def sign(self, digest: bytes) -> bytes:
        """
        Produce an ECDSA-P256/SHA256 signature over the given digest.

        Args:
          digest: 32-byte SHA-256 digest from `hash_approval`.

        Returns:
          Raw ECDSA signature bytes (DER-encoded per PKCS#11 API).
        """
        token = list(self.lib.get_slots(token_present=True))[
            self.slot].get_token()
        with token.open(user_pin=self.pin) as session:
            priv = next(
                session.get_objects({
                    Attribute.LABEL: self.key_label,
                    Attribute.CLASS: ObjectClass.PRIVATE_KEY
                }),
                None
            )
            if priv is None:
                raise RuntimeError(
                    f"Private key with label '{self.key_label}' not found")
            return priv.sign(digest, mechanism=Mechanism.ECDSA_SHA256)


# --- Verification stub --------------------------------------------------------------------------

def verify_approval(signature: bytes, digest: bytes, public_pem: bytes) -> bool:
    """
    Verify an approval signature against its digest using the provided public key.

    Args:
      signature: Raw signature bytes from `PKCS11Signer.sign`.
      digest: SHA-256 digest from `hash_approval`.
      public_pem: Public key in PEM format.

    Returns:
      True if signature is non-empty (PoC stub). In production, use:
        from cryptography.hazmat.primitives.asymmetric import ec
        ec_pub.verify(signature, digest, ec.ECDSA(hashes.SHA256()))
    """
    return len(signature) > 0


# --- Packaging ----------------------------------------------------------------------------------

def package_approvals(approvals: Dict[str, bytes]) -> List[Approval]:
    """
    Convert a dict of {key_id: raw_signature_bytes} into a list of Approval objects.

    Args:
      approvals: Mapping of key_id → raw signature bytes.

    Returns:
      List of `Approval` objects with base64-encoded signatures.
    """
    return [
        Approval(key_id=kid, signer=kid,
                 signature_b64=base64.b64encode(sig).decode("ascii"))
        for kid, sig in approvals.items()
    ]
