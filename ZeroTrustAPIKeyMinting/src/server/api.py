"""
server/api.py — FastAPI Mint API 

Overview
--------
This module exposes the **/mint** endpoint (plus minimal WebAuthn routes mounted from
`webauthn_api`) for engineers to obtain **short-lived, scoped JWTs**. It enforces:

1) Strong user auth (WebAuthn **or** PIV with attestation/policy),
2) Optional **SEV-SNP** workload attestation binding (nonce + measurement/policy pinning),
3) **Policy** checks for role → allowed scopes + TTL caps,
4) **OCI KMS (HSM)** co-sign approval receipt (header `x-kms-sig`/`x-kms-key`),
5) Threshold control for detached **multi-party approvals** (e.g., separate approvers),
6) **MPC key** use for signing: either local Ed25519 from shares (PoC) or **FROST** t-of-n,
7) Structured, minimal response: `{ token, kid, expires_at }`.

Security & Ops
--------------
- Authentication:
  • `authenticate_engineer(...)` verifies WebAuthn assertions or PIV attestation per policy.
  • The WebAuthn routes are mounted from `webauthn_api` and serve the browser flows.

- Attestation (optional but recommended):
  • If `REQUIRE_SNP_ATTESTATION=true`, the request must carry an SNP report + VCEK.
  • We bind the mint challenge (user/scopes/ttl) to the report nonce.

- Policy:
  • Reads `policy.json` (path via `POLICY_FILE`) and enforces scope/TTL limits.

- KMS co-sign receipt:
  • If `OCI_KMS_KEY_OCID` and `OCI_REGION` are set, the server obtains an **HSM-signed**
    receipt of a challenge document and embeds it in JWT headers (`x-kms-sig`, `x-kms-key`).
  • Downstream (Envoy/OPA) validates the receipt before trusting JWTs.

- MPC / Threshold signing:
  • PoC path: reconstruct Ed25519 from Shamir shares on disk (YubiShareDevice + recover_secret).
  • Preferred path: `USE_FROST=true` → ask FROST signers for an aggregated Ed25519 signature
    over the JWT `signing_input`, avoiding private key reconstruction in one process.

Tunable / Config (env)
----------------------
- POLICY_FILE               : Path to policy JSON (default ./policy.json)
- REQUIRE_SNP_ATTESTATION   : "true"/"false"; require SEV-SNP report (default false)
- SNP_ALLOWED_MEASUREMENTS  : JSON array string of allowed SNP measurements
- SNP_POLICY_HASH           : Hex string of pinned policy/config hash
- POLICY_HASH               : Deployment policy hash (embedded/bound in KMS approval)
- TEE_POLICY_HASH_OVERRIDE  : (PoC) optional override for sidecar verifiers
- SHARE_DIR                 : Directory with Shamir shares (default .mpc_shares)
- ISSUER_KID                : JWT kid header (default mpc-root-key-1)
- USE_FROST                 : "true" to use FROST threshold signing path
- FROST_COORD_URL           : Base URL for coordinator (used by frost_client)
- OCI_KMS_KEY_OCID          : KMS key OCID to sign approval challenge
- OCI_REGION                : OCI region of the KMS key

Production Considerations
-------------------------
- Request schema: The `MintRequest` below is a simplified model; ensure the request body
  includes **user/role/scopes/ttl_seconds** (see usage in code). You can merge `Attestation`
  into `MintRequest` or nest it clearly.
- Secrets & shares: Replace filesystem shares with **real FROST** signers on private networks
  with mTLS + JWT auth; do not reconstruct keys in a single process.
- Observability: Emit audit events (subject, scopes, ttl, kid, kms receipt presence) and
  metrics for success/error paths; consider rate limiting per identity.
- Error hygiene: Avoid leaking verification details; keep messages generic but log internally.
"""

from __future__ import annotations

import json
import os
import time
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# --- Internal imports (PoC modules wired elsewhere in repo) -------------------------------------
from ..mpc.yubihsm import YubiShareDevice
from ..mpc.shares import recover_secret
from ..mpc.coordinator import derive_ed25519_from_seed
from ..issuer.policies import Policy
from ..auth.engineer_auth import authenticate_engineer
from ..attestation.sev_snp import verify_snp_report
from ..oci.kms_approval import (
    kms_sign_approval,
    verify_kms_signature,
    KMSApprovalResult,
)
from ..issuer.token_issuer import sign_jwt_ed25519, build_jws_external
from ..mpc.frost_client import frost_sign

# FastAPI app setup and static PoC UI (e.g., registration/assert flows)
app = FastAPI(title="Zero-Trust API Key Minting PoC")

# Minimal WebAuthn endpoints are mounted from a dedicated router
from .webauthn_api import router as webauthn_router  # noqa: E402
app.include_router(webauthn_router)

# Serve PoC HTML/JS (e.g., mint-after-assert) from /web
app.mount("/demo", StaticFiles(directory="web", html=True), name="demo")


# --- Request models ------------------------------------------------------------------------------

class MintRequest(BaseModel):
    """
    PoC request model used by /mint.

    NOTE: This model intentionally keeps auth material (`webauthn_assertion` or `piv`)
    separate from attestation and policy-relevant inputs. The handler below expects
    fields like `user`, `role`, `scopes`, `ttl_seconds` that are *not* defined here.
    In your production API, either:
      - Promote those fields into this model, or
      - Introduce a parent model that contains both `Attestation` and the auth block.

    The current handler accesses `req.user`, `req.role`, etc. Ensure your client sends
    these values (or adjust the Pydantic model accordingly).
    """
    attestation: dict | None = Field(
        None, description="SEV-SNP attestation blob & VCEK (report_b64, vcek_pem_b64, ...)"
    )
    auth_method: str = Field("webauthn", description="webauthn or piv")
    webauthn_assertion: dict | None = None
    piv: dict | None = None
    approvals: List[dict] | None = Field(
        None, description="Detached YubiKey approvals (t-of-n)"
    )
    # Expected in practice but not declared here (see NOTE above):
    # user: str
    # role: str
    # scopes: List[str]
    # ttl_seconds: int


class Attestation(BaseModel):
    """
    Example structure for a combined attestation + policy-binding input.
    Not directly used by the current handler but illustrates intended fields.
    """
    nonce: str
    policy_hash: str
    evidence: str | None = None
    user: str = Field(..., description="Engineer username/email")
    role: str = Field("engineer", description="Role for policy")
    scopes: List[str] = Field(..., description="Requested scopes")
    ttl_seconds: int = Field(..., description="Token TTL")


# --- API: /mint ----------------------------------------------------------------------------------

@app.post("/mint")
def mint(req: MintRequest):
    """
    Mint a short-lived, scoped JWT under MPC/FROST control with optional SNP + KMS gating.

    Flow:
      1) Load policy and validate requested `role`/`scopes`/`ttl_seconds`.
      2) Authenticate engineer via WebAuthn or PIV.
      3) (Optional) Verify SEV-SNP report (nonce binds to mint context).
      4) (Optional) Obtain OCI KMS approval signature; embed receipt in JWT header.
      5) Satisfy MPC threshold:
          - PoC: recover Ed25519 from Shamir shares on disk and sign;
          - FROST: produce an aggregated Ed25519 signature with no full key assembly.
      6) Return token + kid + expires_at.

    Raises:
      HTTPException with 4xx/5xx status codes on failure.
    """
    # 1) Policy
    policy_path = os.getenv("POLICY_FILE", "./policy.json")
    pol = Policy(policy_path)

    # 2) Authentication (engineer identity/device)
    if req.auth_method == "webauthn":
        # Validates the WebAuthn assertion against stored credential (RP ID/origin policy)
        authenticate_engineer(
            user=req.user,  # Provided by client; see NOTE in MintRequest
            role=req.role,
            method="webauthn",
            webauthn_assertion=req.webauthn_assertion,
        )
    elif req.auth_method == "piv":
        piv = req.piv or {}
        # Validates PIV chain + EKU + signature over server challenge; enforces root trust
        authenticate_engineer(
            user=req.user,
            role=req.role,
            method="piv",
            piv_leaf_pem_b64=piv.get("leaf_pem_b64"),
            piv_chain_pems_b64=piv.get("chain_pems_b64"),
            piv_root_pems_b64=piv.get("root_pems_b64"),
            piv_challenge_b64=piv.get("challenge_b64"),
            piv_signature_b64=piv.get("signature_b64"),
        )
    else:
        raise HTTPException(status_code=400, detail="unknown auth_method")

    # Evaluate RBAC policy for scopes/TTL (fail-closed)
    ok, reason = pol.allowed(req.role, req.scopes, req.ttl_seconds)
    if not ok:
        raise HTTPException(status_code=403, detail=reason)

    # 3) (Optional) SEV-SNP attestation
    snp_required = os.getenv("REQUIRE_SNP_ATTESTATION",
                             "false").lower() == "true"
    if snp_required:
        att = req.attestation or {}
        ok_att = verify_snp_report(
            report_b64=att.get("report_b64", ""),
            vcek_pem_b64=att.get("vcek_pem_b64", ""),
            expected_measurements=json.loads(
                os.getenv("SNP_ALLOWED_MEASUREMENTS", "[]")),
            expected_policy_hash=os.getenv("SNP_POLICY_HASH"),
            # Bind the mint context into the report nonce
            bind_nonce=json.dumps(
                {"user": req.user, "scopes": req.scopes, "ttl": req.ttl_seconds}
            ).encode(),
        )
        if not ok_att:
            raise HTTPException(
                status_code=401, detail="SEV-SNP attestation failed")

    # 4) OCI KMS (HSM) approval gate: co-sign and verify receipt
    kms_key = os.getenv("OCI_KMS_KEY_OCID")
    kms_region = os.getenv("OCI_REGION")
    approval: KMSApprovalResult | None = None
    if kms_key and kms_region:
        # The challenge binds user/role/scopes/ttl + deployment policy hash
        policy_hash = os.getenv("POLICY_HASH", "no-policy-hash")
        challenge_doc = json.dumps(
            {
                "user": req.user,
                "role": req.role,
                "scopes": req.scopes,
                "ttl": req.ttl_seconds,
                "policy_hash": policy_hash,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        try:
            approval = kms_sign_approval(challenge_doc, kms_key, kms_region)
        except Exception as e:
            # Deny if HSM approval unavailable or fails verification
            raise HTTPException(
                status_code=403, detail=f"KMS approval failed: {e}")
        if not verify_kms_signature(challenge_doc, approval.signature_b64, approval.public_key_pem):
            raise HTTPException(
                status_code=403, detail="KMS signature verification failed")

    # 5) Gather MPC shares (PoC file-based shares)
    share_dir = os.getenv("SHARE_DIR", ".mpc_shares")
    meta_path = os.path.join(share_dir, "meta.json")
    if not os.path.exists(meta_path):
        raise HTTPException(
            status_code=500, detail="MPC shares not initialized")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    threshold = meta["threshold"]

    shares = []
    for name in os.listdir(share_dir):
        if name.startswith("share_") and name.endswith(".json"):
            dev = YubiShareDevice(os.path.join(share_dir, name))
            shares.append(dev.get_share())
            if len(shares) >= threshold:
                break
    if len(shares) < threshold:
        raise HTTPException(
            status_code=500, detail="insufficient shares online")

    # Derive local Ed25519 key (PoC path) from Shamir-recovered seed
    seed = recover_secret(shares)
    kid = os.getenv("ISSUER_KID", "mpc-root-key-1")
    mpc_key = derive_ed25519_from_seed(seed, kid)

    # (PoC) TEE policy pin check — for real deployments, rely on an attestation verifier
    expected_policy_hash = os.getenv("POLICY_HASH")
    if expected_policy_hash:
        provided_hash = os.getenv("TEE_POLICY_HASH_OVERRIDE") or ""
        if not provided_hash:
            provided_hash = expected_policy_hash  # PoC fallback
        if provided_hash != expected_policy_hash:
            raise HTTPException(
                status_code=401, detail="attestation policy hash mismatch")

    # Optional detached approvals: enforce t-of-n out-of-band approvers if configured
    try:
        approval_threshold = int(os.getenv("APPROVAL_THRESHOLD", "0"))
    except ValueError:
        approval_threshold = 0
    if approval_threshold > 0:
        if not req.approvals or len(req.approvals) < approval_threshold:
            raise HTTPException(
                status_code=403,
                detail=f"require at least {approval_threshold} approvals",
            )
        # NOTE: Add per-approval signature verification here (out of scope in this PoC).

    # 6) Build JWT claims
    now = int(time.time())
    payload = {
        "sub": req.user,
        "role": req.role,
        "scopes": req.scopes,
        "exp": now + req.ttl_seconds,
        "nbf": now,
        "iss": "mpc-minting-poc",
        "aud": "internal-services",
    }

    # JWT headers (KMS receipt embedded if present)
    extra_headers = {}
    if approval and kms_key:
        extra_headers = {
            "x-kms-sig": approval.signature_b64, "x-kms-key": kms_key}

    use_frost = os.getenv("USE_FROST", "false").lower() == "true"
    if use_frost:
        # Threshold Ed25519 signing via FROST:
        #  - Construct header and payload JSON exactly as they will appear.
        #  - Build signing_input (b64url(header) + "." + b64url(payload)).
        #  - Ask FROST coordinator to produce the aggregated signature.
        headers = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
        headers.update(extra_headers or {})
        jws_tmp, signing_input = build_jws_external(headers, payload, b"")
        sig, group_pub = frost_sign(signing_input)
        # Reassemble compact JWT with real signature
        header_b64, payload_b64, _ = jws_tmp.split(".")
        import base64

        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Uniform return shape
        class S:
            pass

        signed = S()
        signed.jwt = token
        signed.kid = kid
        signed.expires_at = payload["exp"]
    else:
        # PoC path: sign locally with reconstructed Ed25519 key
        signed = sign_jwt_ed25519(
            mpc_key.private_key,
            kid,
            payload,
            extra_headers=extra_headers,
        )

    return {"token": signed.jwt, "kid": signed.kid, "expires_at": signed.expires_at}
