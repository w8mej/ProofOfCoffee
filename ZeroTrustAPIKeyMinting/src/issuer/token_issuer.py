"""
tokens/eddsa_sign.py — Ed25519 JWT signing and external-JWS assembly (documented)

Security & Ops
- Purpose:
  1) `sign_jwt_ed25519` signs a JWT using an **in-memory Ed25519** private key and
     optionally embeds an OCI KMS co-sign receipt in the header (`x-kms-sig`).
  2) `build_jws_external` assembles a compact JWS when you’ve computed the signature
     **outside the process** (e.g., via FROST threshold signers or HSM). It returns
     both the compact token and the exact `signing_input` bytes that must be signed:
       signing_input = base64url(header) + "." + base64url(payload)

- Headers:
  • `alg` is **EdDSA** (Ed25519 per RFC 8037) to align with threshold Ed25519 (FROST).
  • `kid` identifies the logical signing key (or group public key).
  • Optional `x-kms-sig` carries a KMS-signed receipt (base64url-opaque) for OPA checks.

- Trust boundaries:
  • This module does not fetch keys; it receives an already-initialized key object
    or signature bytes from a trusted signer service.
  • Caller must ensure `payload["exp"]` is set; short TTLs are strongly recommended.

Tunable / Config
- Header pass-through: `extra_headers` allows adding fields like `x-kms-key` (the KMS key OCID)
  or `cty` if you have nested JWTs. These are merged onto the base header.
- Time claims: The function sets `iat` if missing. You may pre-set `nbf` upstream.

Production Readiness / Improvements
- Key handling:
  • Prefer signing via **FROST threshold signers** or OCI KMS Ed25519 if available,
    using `build_jws_external` to assemble the compact JWT from an external signature.
- Receipts:
  • Include both `x-kms-sig` and `x-kms-key` (OCID) to enable precise OPA validation.
- Validation:
  • Add schema validation for payload claims (iss, aud, sub, scp, exp).
  • Ensure header size constraints; avoid overly large custom headers.
- Audit:
  • Emit an append-only audit event with `kid`, `exp`, `sub`, `scp`, and receipt presence.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ed25519


ALG = "EdDSA"


@dataclass
class SignedToken:
    """Return type for successfully signed tokens."""
    jwt: str
    kid: str
    expires_at: int


def sign_jwt_ed25519(
    priv: ed25519.Ed25519PrivateKey,
    kid: str,
    payload: Dict,
    *,
    kms_signature_b64: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> SignedToken:
    """
    Sign a JWT using an Ed25519 private key (in-memory) and return the compact token.

    Args:
      priv: Ed25519 private key object (from `cryptography`).
      kid: Key identifier to place in the JWT header.
      payload: JWT claims; MUST include an `exp` (unix seconds). `iat` is set if missing.
      kms_signature_b64: Optional base64url (or base64) KMS co-sign receipt to embed as `x-kms-sig`.
      extra_headers: Optional dict of additional JOSE headers to merge (e.g., {"x-kms-key": "<ocid>"}).

    Returns:
      SignedToken(jwt, kid, expires_at)

    Raises:
      ValueError if `exp` is missing or invalid, or if signing fails.
    """
    if "exp" not in payload:
        raise ValueError("payload.exp is required (unix epoch seconds)")

    headers: Dict[str, str] = {"alg": ALG, "kid": kid, "typ": "JWT"}
    if extra_headers:
        # Merge but do not allow overriding alg/kid/typ
        for k, v in extra_headers.items():
            if k.lower() in {"alg", "kid", "typ"}:
                continue
            headers[k] = v
    if kms_signature_b64:
        headers["x-kms-sig"] = kms_signature_b64

    now = int(time.time())
    payload.setdefault("iat", now)

    # PyJWT supports passing the `cryptography` key object directly for EdDSA.
    try:
        token = jwt.encode(payload, key=priv, algorithm=ALG, headers=headers)
    except Exception as e:
        raise ValueError(f"Ed25519 signing failed: {e}")

    return SignedToken(jwt=token, kid=kid, expires_at=int(payload["exp"]))


# ---- External JWS assembly helpers -------------------------------------------------------------

def _b64u(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_jws_external(
    headers: Dict,
    payload: Dict,
    signature_bytes: bytes,
) -> Tuple[str, bytes]:
    """
    Assemble a compact JWS from externally-computed signature bytes.

    This is the preferred path when **FROST signers** (or any HSM/KMS) produce the
    Ed25519 signature. You construct the header/payload JSON *exactly* as they will
    appear in the token, compute the `signing_input`, ask the external signer to sign
    it with Ed25519, then pass the signature here to receive the final compact JWS.

    Args:
      headers: JOSE header dict (include `alg=EdDSA` and `kid`, plus optional `x-kms-sig`).
      payload: JWT claims dict (must include `exp`; ideally include `iat`, `nbf`).
      signature_bytes: Raw signature bytes returned by the external signer.

    Returns:
      (token, signing_input)
        token         : compact JWS string "base64url(header).base64url(payload).base64url(sig)"
        signing_input : bytes exactly equal to "base64url(header).base64url(payload)" (no trailing dot)

    Notes:
      • JSON is serialized with separators=(",", ":"), ensuring no extraneous whitespace.
      • The signer must sign **signing_input** as bytes; Ed25519 will produce a 64-byte signature.
    """
    header_b64 = _b64u(json.dumps(
        headers, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64u(json.dumps(
        payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = _b64u(signature_bytes)
    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    return token, signing_input
