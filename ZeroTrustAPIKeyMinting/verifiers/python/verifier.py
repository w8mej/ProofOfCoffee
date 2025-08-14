#!/usr/bin/env python3
"""
verifier.py — End-to-end verifier for minted tokens 

Overview
--------
A tiny, dependency-light CLI/SDK that validates:
  1) The JWT produced by the mint service (EdDSA/Ed25519),
  2) The OCI KMS co-sign receipt carried out-of-band in the JWT header
     (headers `x-kms-sig` and `x-kms-key`) by verifying the RSA signature over
     the canonical mint challenge bytes.

It is meant to be embedded as a library (import functions) or invoked as a CLI
for local validation and troubleshooting.

Security & Ops
--------------
- **Trust anchors**
  • Ed25519 public key (PEM) for verifying the JWT signature. In production,
    distribute via a secure channel (config repo with code review, KMS, Vault, or JWKS).
  • OCI KMS public key (PEM) for the specific key OCID that co-signed the challenge.
    Rotate safely; allow multiple active keys if needed.

- **What is verified**
  • JWT: Verified with EdDSA (Ed25519). We reject tokens with invalid signatures,
    wrong algorithm, or expired/nbf-in-the-future.
  • KMS receipt: RSA SHA-256 over the **original challenge bytes**. The mint service
    signed SHA-256(challenge) with KMS using message_type="DIGEST". Verifiers should
    hash the original challenge once and verify the signature with PKCS#1 v1.5
    (or PSS if you switch algorithms consistently).

- **Replay & binding**
  • This verifier assumes the caller provides the exact canonical challenge JSON
    used at mint time (e.g., sorted keys, compact form). Producers and verifiers
    MUST agree on the exact serialization to prevent ambiguity.

Tunable / Config
----------------
- Algorithms:
  • JWT: fixed to EdDSA (Ed25519).
  • KMS: defaults to PKCS#1 v1.5 (to match PoC); switchable in code to RSA-PSS.
- Claims enforcement:
  • This sample enforces `exp`, `nbf`, and accepts any audience/issuer by default.
    Pass `audience` and `issuer` if you want strict checks (see `verify_jwt()`).

Production Improvements
-----------------------
- Support multiple Ed25519 keys (kid→PEM/JWKS), select by JWT `kid`.
- Support multiple KMS keys (x-kms-key→PEM) for rotation/regions and verify that
  `x-kms-key` is in an allowlist for the environment.
- Strict canonicalization helper for the challenge (stable key order, UTF-8,
  explicit separators) shared across services (producer/consumer).
- Expose rich errors and metrics (Prometheus counters) for allow/deny outcomes.

Usage
-----
CLI:
  python verifier.py \
    --jwt token.jwt \
    --ed25519-pub ed25519_pub.pem \
    --kms-sig "$(jq -r '.header.x-kms-sig' token.json)" \
    --kms-pub kms_pub.pem \
    --challenge-json challenge.json \
    [--aud internal-services] [--iss mpc-minting-poc]

Library:
  from verifier import verify_jwt, verify_kms_receipt
  hdr, claims = verify_jwt(token, ed25519_pub_pem, audience="internal-services", issuer="mpc-minting-poc")
  ok = verify_kms_receipt(challenge_bytes, kms_sig_b64, kms_pub_pem)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from typing import Any, Dict, Optional

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def verify_jwt(
    token: str,
    ed25519_pub_pem: str,
    *,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
    leeway: int = 0,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Verify an EdDSA (Ed25519) JWT and return (header, claims).

    Parameters
    ----------
    token : str
        Compact JWS (base64url) string.
    ed25519_pub_pem : str
        PEM-encoded Ed25519 public key (SubjectPublicKeyInfo / SPKI).
    audience : Optional[str]
        Expected `aud` claim. If provided, the verifier enforces it.
    issuer : Optional[str]
        Expected `iss` claim. If provided, the verifier enforces it.
    leeway : int
        Allowed clock skew in seconds for `exp`/`nbf`.

    Returns
    -------
    (header, claims) : (dict, dict)

    Raises
    ------
    jwt.PyJWTError on signature/claims failures or malformed tokens.
    """
    # Load Ed25519 public key
    pub = serialization.load_pem_public_key(ed25519_pub_pem.encode("utf-8"))
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise ValueError("ed25519_pub_pem is not an Ed25519 public key")

    # Decode header early (to inspect `kid`, `x-kms-sig`, etc.)
    header = jwt.get_unverified_header(token)

    # Build PyJWT validation options
    options = {
        "require": ["exp", "nbf"],  # always require freshness bounds
    }

    # Prepare kwargs for audience/issuer if provided
    decode_kwargs: Dict[str, Any] = {
        "algorithms": ["EdDSA"],
        "options": options,
        "leeway": leeway,
    }
    if audience:
        decode_kwargs["audience"] = audience
    if issuer:
        decode_kwargs["issuer"] = issuer

    # Perform signature + claims verification
    claims = jwt.decode(token, key=pub, **decode_kwargs)

    return header, claims


def verify_kms_receipt(challenge: bytes, kms_sig_b64: str, kms_pub_pem: str) -> bool:
    """
    Verify the OCI KMS co-sign receipt using RSA PKCS#1 v1.5 over SHA-256(challenge).

    Parameters
    ----------
    challenge : bytes
        The exact canonical challenge bytes that the mint API constructed and submitted to KMS.
    kms_sig_b64 : str
        Base64-encoded signature returned by KMS (header `x-kms-sig`).
    kms_pub_pem : str
        PEM-encoded RSA public key (from OCI KMS Management get_public_key).

    Returns
    -------
    bool : True if signature verifies, False otherwise.

    Notes
    -----
    - The mint service used message_type="DIGEST" with KMS, passing SHA-256(challenge).
      Therefore, we compute the same digest and verify with RSA/PKCS#1 v1.5 + SHA-256.
    - If you switch to RSA-PSS for KMS, replace padding.PKCS1v15() with
      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH).
    """
    pub = load_pem_public_key(kms_pub_pem.encode("utf-8"))
    sig = base64.b64decode(kms_sig_b64)
    digest = hashlib.sha256(challenge).digest()

    try:
        pub.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def _load_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify Ed25519 JWT and OCI KMS co-sign receipt")
    ap.add_argument("--jwt", required=True,
                    help="Path to file containing compact JWS (token)")
    ap.add_argument("--ed25519-pub", required=True,
                    help="Path to Ed25519 public key PEM")
    ap.add_argument("--kms-sig", required=True,
                    help="Base64 KMS signature (x-kms-sig header value)")
    ap.add_argument("--kms-pub", required=True,
                    help="Path to KMS public key PEM")
    ap.add_argument(
        "--challenge-json",
        required=True,
        help="Path to the EXACT canonical challenge bytes (e.g., compact JSON) used at mint time",
    )
    ap.add_argument("--aud", default=None,
                    help="Expected audience claim (optional)")
    ap.add_argument("--iss", default=None,
                    help="Expected issuer claim (optional)")
    ap.add_argument("--leeway", type=int, default=0,
                    help="Clock skew leeway in seconds")
    args = ap.parse_args()

    token = _load_file(args.jwt).decode("utf-8").strip()
    ed_pub_pem = _load_file(args.ed25519_pub).decode("utf-8")
    kms_pub_pem = _load_file(args.kms_pub).decode("utf-8")
    challenge = _load_file(args.challenge_json)

    try:
        hdr, payload = verify_jwt(
            token,
            ed_pub_pem,
            audience=args.aud,
            issuer=args.iss,
            leeway=args.leeway,
        )
        print("header:", json.dumps(hdr, indent=2))
        print("payload:", json.dumps(payload, indent=2))
    except jwt.PyJWTError as e:
        print(f"jwt_verify_error: {e}")
        return 2
    except Exception as e:
        print(f"jwt_input_error: {e}")
        return 2

    ok = verify_kms_receipt(challenge, args.kms_sig, kms_pub_pem)
    print("kms_receipt_ok:", bool(ok))
    return 0 if ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
