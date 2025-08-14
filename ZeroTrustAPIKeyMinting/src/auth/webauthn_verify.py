"""
auth/webauthn_verify.py — Minimal WebAuthn (FIDO2) registration & assertion verify (PoC)

Security & Ops
- Purpose: Persist a WebAuthn credential (public key + credential ID) at registration
  and later verify an assertion (authenticatorData + clientDataJSON + signature) for login/mint.

- What this PoC verifies:
  1) **RP ID binding**: rpIdHash in authenticatorData equals SHA-256(WEBAUTHN_RP_ID).
  2) **Origin binding**: clientDataJSON.origin equals WEBAUTHN_ORIGIN.
  3) **Signature**: Using the registered public key over authenticatorData || SHA256(clientDataJSON),
     with the correct signature scheme (EC P-256 ECDSA-SHA256 or RSA PKCS#1v1.5 SHA-256).
  4) **Replay resistance**: signCount monotonic increase (very basic clone detection).
  5) **Credential match**: rawId equals stored credential_id.

- Trust boundaries:
  • Registration still uses server=stateless flow for the PoC (no server-side challenge tracking).
    In production, **track challenge state** and require attestation conveyance policy.
  • The credential store is file-based JSON; **replace with durable DB** + encryption at rest.

Tunable / Config
- WEBAUTHN_STORE : Path to JSON credential store (default: ./webauthn_store.json).
- WEBAUTHN_RP_ID : Relying Party ID (eTLD+1 style; must match browser domain).
- WEBAUTHN_ORIGIN: Exact origin (scheme+host+port) expected in clientDataJSON.origin.

Production Readiness / Improvements
- Registration:
  • Provide a server-generated challenge (track in-memory/DB) and pass as Fido2Server state.
  • Enforce **attestation** policy (packed/android-key/tpm), verify AAGUID, and pin device metadata.
  • Store multiple credentials per user; support resident credentials; require **user verification (UV)**.

- Assertion:
  • Enforce `clientDataJSON.type == "webauthn.get"`; verify challenge matches server state.
  • Persist and verify **signCount** strictly; treat non-increment as potential key cloning.
  • Rate limit by IP/identity; store recent challenges for replay detection.
  • Audit log success/denies with reason codes (no secrets).

- Crypto:
  • Support COSE algorithms exhaustively (ES256/RS256/EdDSA if registered).
  • Constant-time comparisons for IDs and hashes where applicable.
"""

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

# Simple file-based credential store (username -> credential public key + credential id + counters)
STORE_PATH = os.getenv("WEBAUTHN_STORE", "./webauthn_store.json")


def _load_store() -> Dict[str, Any]:
    """Load the credential store JSON from disk (PoC)."""
    if not os.path.exists(STORE_PATH):
        return {}
    with open(STORE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_store(d: Dict[str, Any]) -> None:
    """Persist the credential store JSON to disk (PoC)."""
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)


def register_complete(
    rp_id: str,
    origin: str,
    username: str,
    registration_response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Complete a WebAuthn registration ceremony (attestation) and persist the credential.

    Args:
      rp_id: Relying Party ID (must match browser domain subset).
      origin: Expected origin (scheme://host[:port]) from clientDataJSON.
      username: Application username.
      registration_response: Dict with base64 fields: attestationObject, clientDataJSON.

    Returns:
      Persisted credential record for this username.

    NOTE: This PoC uses a stateless `Fido2Server` call (state=None). In production, you
    must create a server challenge and pass it through the ceremony for replay protection.
    """
    # Minimal FIDO2 server (stateless in PoC). In production, use real `register_begin`/`register_complete`.
    server = Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name=rp_id))

    # Decode client payload
    att_obj_b = base64.b64decode(registration_response["attestationObject"])
    client_data_b = base64.b64decode(registration_response["clientDataJSON"])

    # Complete registration; this returns credential data (id, public key, signCount)
    auth_data = server.register_complete(
        state=None,  # PoC-only; do not do this in production
        client_data=client_data_b,
        attestation_object=att_obj_b,
    )

    # Persist credential for the user (single cred per user in PoC)
    store = _load_store()
    store[username] = {
        "credential_id": base64.b64encode(auth_data.credential_id).decode("utf-8"),
        "public_key_pem": auth_data.credential_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        "sign_count": int(auth_data.sign_count),
        "rp_id": rp_id,
        "origin": origin,
        "registered_at": int(time.time()),
    }
    _save_store(store)
    return store[username]


def _parse_client_data(client_data_json_b: bytes) -> Dict[str, Any]:
    """Parse clientDataJSON and return the decoded JSON object."""
    try:
        return json.loads(client_data_json_b.decode("utf-8"))
    except Exception:
        return {}


def _parse_sign_count(authenticator_data_b: bytes) -> int:
    """
    Extract signCount from authenticatorData (bytes 33..36 big-endian).

    Structure:
      0..31   rpIdHash (32 bytes)
      32      flags (1 byte)
      33..36  signCount (4 bytes, big-endian)
      ...
    """
    if len(authenticator_data_b) < 37:
        return 0
    return int.from_bytes(authenticator_data_b[33:37], "big")


def _verify_signature(pubkey_pem: str, signature_b: bytes, signed_bytes_b: bytes) -> bool:
    """
    Verify WebAuthn assertion signature using stored PEM public key.

    Supports EC P-256 (ES256) and RSA (RS256) keys for PoC.
    """
    try:
        pub = load_pem_public_key(pubkey_pem.encode("utf-8"))
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature_b, signed_bytes_b, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature_b, signed_bytes_b,
                       padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except Exception:
        return False


def assert_verify(
    rp_id: str,
    origin: str,
    username: str,
    assertion_response: Dict[str, Any],
) -> bool:
    """
    Verify a WebAuthn assertion against the stored credential for `username`.

    Args:
      rp_id: Relying Party ID (hash compared to authenticatorData[0:32]).
      origin: Expected origin string in clientDataJSON.origin.
      username: User to lookup the stored credential for.
      assertion_response: Dict with base64 fields:
        - authenticatorData
        - clientDataJSON
        - signature
        - rawId

    Returns:
      True on successful verification (rpIdHash, origin, signature, signCount monotonic).
    """
    # 0) Load stored credential
    store = _load_store()
    cred = store.get(username)
    if not cred:
        return False

    # 1) Decode inputs
    authenticator_data = base64.b64decode(
        assertion_response["authenticatorData"])
    client_data_json = base64.b64decode(assertion_response["clientDataJSON"])
    signature = base64.b64decode(assertion_response["signature"])
    raw_id = base64.b64decode(assertion_response["rawId"])

    # 2) Credential ID match (constant-time compare where possible)
    try:
        stored_cred_id = base64.b64decode(cred["credential_id"])
    except Exception:
        return False
    if len(raw_id) != len(stored_cred_id) or hashlib.sha256(raw_id).digest() != hashlib.sha256(stored_cred_id).digest():
        # Approximate constant-time by hashing both sides; better to use hmac.compare_digest on same-length encodings
        return False

    # 3) RP ID binding: SHA256(rp_id) must match rpIdHash in authenticatorData
    expected_rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if authenticator_data[:32] != expected_rp_hash:
        return False

    # 4) Origin binding & basic clientData checks
    client = _parse_client_data(client_data_json)
    if not client or client.get("type") != "webauthn.get" or client.get("origin") != origin:
        return False
    # (Production) Also verify client["challenge"] matches server-issued challenge (base64url)

    # 5) Signature base = authenticatorData || SHA256(clientDataJSON)
    client_hash = hashlib.sha256(client_data_json).digest()
    signed_bytes = authenticator_data + client_hash

    # 6) Crypto verify using stored public key
    if not _verify_signature(cred["public_key_pem"], signature, signed_bytes):
        return False

    # 7) Replay resistance: verify signCount monotonic
    new_sc = _parse_sign_count(authenticator_data)
    old_sc = int(cred.get("sign_count", 0))
    if new_sc != 0 and old_sc != 0 and new_sc <= old_sc:
        # Non-incrementing counter indicates possible cloned key — deny
        return False

    # 8) Persist updated signCount
    cred["sign_count"] = max(old_sc, new_sc)
    store[username] = cred
    _save_store(store)

    return True
