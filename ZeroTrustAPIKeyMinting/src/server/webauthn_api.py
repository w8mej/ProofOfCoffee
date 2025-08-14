"""
webauthn_api.py — Minimal WebAuthn registration & assertion routes (documented)

Overview
--------
This router provides **/webauthn/register/start**, **/webauthn/register/finish**,
**/webauthn/assert/start**, and **/webauthn/assert** endpoints used by the browser
to enroll and assert a platform or roaming authenticator. It integrates with the PoC
store used by `auth/webauthn_verify.py`.

Security & Ops
--------------
- Challenge binding:
  • We create a fresh, random, **base64url** challenge per flow and return it to the browser.
  • In production, persist the challenge server-side and bind it to the session/user.
- RP policy:
  • `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` must reflect your real domain(s).
    Mismatch will (correctly) break verification.
- Replay resistance:
  • This PoC does not persist challenge usage beyond the request; real systems should
    store challenges (and WebAuthn `sign_count`) and **invalidate** them after use.
- Credential store:
  • The PoC stores user credential public keys in a local JSON file (`WEBAUTHN_STORE`).
    Replace with a database, enable backups, and protect at rest.

Tunable / Config
----------------
- WEBAUTHN_RP_ID     : RP ID sent to browser and verified server-side (default: "localhost")
- WEBAUTHN_ORIGIN    : Expected origin (scheme+host+port) (default: "http://localhost:8080")
- WEBAUTHN_STORE     : Path to credential store JSON (default: "./webauthn_store.json")

Production Considerations
-------------------------
- Attestation policy:
  • For high assurance, enforce attestation during registration (AAGUID allow-list, MDS trust).
  • Here we set `attestation: "none"` for simplicity.
- Algorithms:
  • We advertise `-7` (ES256) in `pubKeyCredParams` for broad compatibility.
    You may add `-8` (EdDSA/Ed25519) for newer authenticators & libraries.
- Sign counter:
  • Track and enforce monotonic `sign_count` to detect cloned authenticators.
- Session CSRF:
  • These routes are JSON POSTs; still apply CSRF protections (double-submit or SameSite).

Routes
------
POST /webauthn/register/start
POST /webauthn/register/finish
POST /webauthn/assert/start
POST /webauthn/assert
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..auth.webauthn_verify import register_complete, assert_verify

router = APIRouter(prefix="/webauthn", tags=["webauthn"])

# Simple in-memory challenge cache for the PoC.
# In production, store challenges per user/session with TTL and single-use semantics.
CHALLENGES: dict[str, str] = {}


# ----------------------------- Request models ----------------------------------------------------

class StartReq(BaseModel):
    username: str = Field(..., description="User handle (e.g., email)")


class FinishReq(BaseModel):
    username: str
    attestationObject: str
    clientDataJSON: str


class AssertReq(BaseModel):
    username: str
    rawId: str
    authenticatorData: str
    clientDataJSON: str
    signature: str


# ----------------------------- Registration ------------------------------------------------------

@router.post("/register/start")
def start_register(req: StartReq):
    """
    Begin WebAuthn registration.

    Returns:
      A dictionary with RP ID, challenge, `user` object, and `pubKeyCredParams` for the browser.
    """
    # Fresh random (32 bytes) base64url challenge without padding
    challenge = base64.urlsafe_b64encode(
        secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    CHALLENGES[req.username] = challenge

    rp_id = os.getenv("WEBAUTHN_RP_ID", "localhost")

    # Minimal creation options (PublicKeyCredentialCreationOptions minus boilerplate)
    # Attestation is "none" for this PoC; production may require "direct" + MDS validation.
    return {
        "rpId": rp_id,
        "challenge": challenge,
        "user": {
            "name": req.username,
            "id": base64.urlsafe_b64encode(req.username.encode("utf-8")).decode("ascii"),
        },
        # Advertise ES256 for compatibility; consider adding EdDSA (-8) if your libs support it.
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "timeout": 60000,
        "attestation": "none",
    }


@router.post("/register/finish")
def finish_register(req: FinishReq):
    """
    Complete WebAuthn registration.

    Validates the attestation with `register_complete` and persists the credential
    public key for the username in the PoC JSON store.
    """
    expected = CHALLENGES.get(req.username)
    if not expected:
        raise HTTPException(
            status_code=400, detail="start not called or challenge expired")

    rp_id = os.getenv("WEBAUTHN_RP_ID", "localhost")
    origin = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8080")

    reg = {"attestationObject": req.attestationObject,
           "clientDataJSON": req.clientDataJSON}
    info = register_complete(rp_id, origin, req.username, reg)

    # One-time use challenge: drop after successful registration
    CHALLENGES.pop(req.username, None)

    # Only return the credential ID; public key is stored server-side by register_complete
    return {"ok": True, "stored": {"credential_id": info["credential_id"]}}


# ----------------------------- Assertion (login) -------------------------------------------------

@router.post("/assert/start")
def start_assert(req: StartReq):
    """
    Begin WebAuthn assertion (authentication).

    Looks up the stored credential for the user and returns assertion options with a new challenge.
    """
    store_path = os.getenv("WEBAUTHN_STORE", "./webauthn_store.json")
    try:
        with open(store_path, "r", encoding="utf-8") as f:
            store = json.load(f)
    except Exception:
        store = {}

    cred = store.get(req.username)
    if not cred:
        raise HTTPException(status_code=404, detail="no credential for user")

    challenge = base64.urlsafe_b64encode(
        secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    CHALLENGES[req.username] = challenge

    rp_id = os.getenv("WEBAUTHN_RP_ID", "localhost")
    return {
        "rpId": rp_id,
        "challenge": challenge,
        # Allow only the stored credential for this user (username → single credential in PoC)
        "allowCredentials": [{"id": cred["credential_id"], "type": "public-key"}],
        "timeout": 60000,
    }


@router.post("/assert")
def assert_login(req: AssertReq):
    """
    Complete WebAuthn assertion.

    Verifies the signature using the stored credential public key. In production, also
    validate and consume the outstanding `challenge` for the username and enforce
    monotonic `sign_count` to detect cloned authenticators.
    """
    rp_id = os.getenv("WEBAUTHN_RP_ID", "localhost")
    origin = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8080")

    # OPTIONAL (recommended in production):
    #   expected_chal = CHALLENGES.pop(req.username, None)
    #   if not expected_chal: raise HTTPException(400, "challenge missing/expired")
    # This PoC delegates challenge + signature validation to assert_verify.

    ok = assert_verify(
        rp_id,
        origin,
        req.username,
        {
            "rawId": req.rawId,
            "authenticatorData": req.authenticatorData,
            "clientDataJSON": req.clientDataJSON,
            "signature": req.signature,
        },
    )
    if not ok:
        raise HTTPException(status_code=401, detail="assertion failed")

    # Consume challenge on success (PoC best-effort)
    CHALLENGES.pop(req.username, None)

    return {"ok": True}
