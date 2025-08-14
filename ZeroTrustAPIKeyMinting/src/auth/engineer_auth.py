"""
auth/engineer_auth.py — Strong engineer authentication (WebAuthn or PIV) with device attestation

Security & Ops
- Purpose: Establish an **EngineerIdentity** that is strongly bound to a hardware-backed factor:
  • WebAuthn (FIDO2) assertion (device-bound credential; resident or server-side), or
  • YubiKey PIV certificate + policy-validated attestation chain and challenge signature.

- What this function guarantees when it returns successfully:
  • The caller proved possession of the WebAuthn private key for `rp_id/origin` OR
    proved possession of the PIV key that chains to your trusted attestation roots.
  • The returned identity is annotated with `method` and `device_attested=True`
    so downstream mint policy can require hardware-backed auth.

- Threat boundaries:
  • WebAuthn relies on RP ID + origin binding; **set WEBAUTHN_RP_ID/WEBAUTHN_ORIGIN correctly**.
  • PIV relies on validating certificate chain to **trusted attestation roots** and enforcing
    policy in `verify_piv_attestation` (alg/key usage/AAGUID-like constraints, etc.).

Tunable / Config
- WEBAUTHN_RP_ID   : e.g., "mint.example.com" (must match browser’s effective domain).
- WEBAUTHN_ORIGIN  : e.g., "https://mint.example.com".
- Policy is enforced in helpers:
  • `webauthn_verify.assert_verify(...)` controls origin/RP ID, counter/replay, user verification.
  • `piv.verify_piv_attestation(...)` controls trust anchors, EKU/policy OIDs, metadata, CRLs/OCSP.

Production Readiness / Improvements
- WebAuthn:
  • Enforce **user verification** (UV) and **attestation conveyance** policy at registration time.
  • Track and verify `signCount` to detect cloned credentials (replay).
  • Persist credential public keys per user; rotate on key compromise.
- PIV:
  • Enforce **CRL/OCSP** checks; pin required **Policy OIDs**; verify firmware/AAGUID metadata
    via your maintained trust store (certs/README.md).
  • Bind challenge to nonce with strict TTL to prevent replay; store recent nonces.
- Common:
  • Rate limit per-identity; emit audit events; fail closed on parsing/verify errors.
  • Return structured error codes (do not leak crypto detail to clients).
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import base64
import os

# Verifies WebAuthn assertion per RP/Origin/policy
from .webauthn_verify import assert_verify
# Verifies PIV chain + challenge signature
from .piv import verify_piv_attestation


@dataclass
class EngineerIdentity:
    """
    Strongly-authenticated engineer identity for mint policy decisions.

    Fields:
      user             : Application username (directory principal or handle).
      role             : Logical role for policy (e.g., "engineer", "sre").
      device_attested  : True iff hardware-backed verification succeeded.
      method           : "webauthn" or "piv" — indicates auth mechanism used.
    """
    user: str
    role: str                   # e.g., "engineer", "sre"
    device_attested: bool
    method: str                 # "webauthn" | "piv"


def authenticate_engineer(
    user: str,
    role: str = "engineer",
    method: str = "webauthn",
    *,
    # WebAuthn inputs (browser POST to /assert forwards these)
    webauthn_assertion: Optional[Dict[str, Any]] = None,
    # PIV inputs (approver CLI or browser uploads)
    piv_leaf_pem_b64: Optional[str] = None,
    piv_chain_pems_b64: Optional[List[str]] = None,
    piv_root_pems_b64: Optional[List[str]] = None,
    piv_challenge_b64: Optional[str] = None,
    piv_signature_b64: Optional[str] = None,
) -> EngineerIdentity:
    """
    Authenticate an engineer using WebAuthn or PIV and return an attested identity.

    Args:
      user: Logical username (subject for JWT `sub`).
      role: Role used by mint policy (controls scopes/TTL caps).
      method: "webauthn" or "piv".
      webauthn_assertion: Dict payload from the browser’s WebAuthn `get()` (assertion).
      piv_leaf_pem_b64: base64(PEM) of the PIV leaf certificate.
      piv_chain_pems_b64: base64(PEM) intermediates (optional).
      piv_root_pems_b64: base64(PEM) trusted attestation **roots** (required).
      piv_challenge_b64: base64 challenge bytes the server issued.
      piv_signature_b64: base64 signature over the challenge produced by the PIV key.

    Returns:
      EngineerIdentity with device_attested=True on success.

    Raises:
      ValueError on missing inputs or verification failure. Fail closed.
    """
    # RP ID and Origin are part of the WebAuthn trust boundary — they must reflect
    # the public origin the browser uses or assertions will (correctly) fail.
    rp_id = os.getenv("WEBAUTHN_RP_ID", "localhost")
    origin = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8080")

    if method == "webauthn":
        # Require the WebAuthn assertion payload (authenticatorData, clientDataJSON, signature, id, rawId, etc.)
        if not webauthn_assertion:
            raise ValueError("webauthn_assertion required")

        # assert_verify() should enforce:
        #  - RP ID hash matches rp_id
        #  - clientDataJSON.origin == origin
        #  - tokenBinding/userVerification per policy
        #  - signCount monotonic (replay/cloning detection)
        ok = assert_verify(
            rp_id=rp_id,
            origin=origin,
            username=user,
            assertion_response=webauthn_assertion,
        )
        if not ok:
            raise ValueError("WebAuthn assertion verification failed")

        return EngineerIdentity(
            user=user,
            role=role,
            device_attested=True,
            method="webauthn",
        )

    elif method == "piv":
        # Validate presence of required PIV inputs (roots and challenge/signature are mandatory)
        if not all([piv_leaf_pem_b64, piv_root_pems_b64, piv_challenge_b64, piv_signature_b64]):
            raise ValueError("piv attestation parameters required")

        # Decode inputs (fail closed on decode errors)
        leaf = base64.b64decode(piv_leaf_pem_b64)
        chain = [base64.b64decode(p) for p in (piv_chain_pems_b64 or [])]
        roots = [base64.b64decode(p) for p in piv_root_pems_b64]
        challenge = base64.b64decode(piv_challenge_b64)
        signature = base64.b64decode(piv_signature_b64)

        # verify_piv_attestation() should enforce:
        #  - Full chain to a trusted attestation root (Yubico PIV Attestation CA, etc.)
        #  - EKU / Policy OIDs as required
        #  - Signature over the server-provided challenge (nonce binding, anti-replay)
        #  - Optional CRL/OCSP and metadata checks per policy
        res = verify_piv_attestation(
            leaf_cert_pem=leaf,
            chain_pems=chain,
            root_pems=roots,
            challenge=challenge,
            signature=signature,
        )
        # Expect a structured result object with `policy_ok` boolean and optional details.
        if not getattr(res, "policy_ok", False):
            raise ValueError("PIV policy failed")

        return EngineerIdentity(
            user=user,
            role=role,
            device_attested=True,
            method="piv",
        )

    else:
        raise ValueError("unknown authentication method")
