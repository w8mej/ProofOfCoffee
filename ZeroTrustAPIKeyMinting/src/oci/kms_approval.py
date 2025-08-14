"""
oci/kms_approval.py — OCI KMS (HSM) approval-signing helper (documented)

Purpose
-------
Provide a lightweight helper to:
  1) Produce an **HSM-backed approval signature** over a server challenge using
     Oracle Cloud Infrastructure **Key Management (KMS/Vault)**, and
  2) Optionally verify the signature locally using the KMS key’s public key.

This approval signature is **separate from JWT signing**. It’s intended for control-plane
gates (e.g., “an HSM key in tenancy X explicitly approved this mint”), which downstream
OPA/Envoy policy can enforce by validating the KMS receipt (signature + key OCID).

Security & Ops
--------------
- Key custody: Private material remains inside OCI HSMs. We call the **Crypto** endpoint to sign.
- Identity to KMS:
  • Prefer **Instance Principals** on OCI (especially CVMs) — no static creds on disk.
  • Fallback to local `~/.oci/config` profile if instance principals are unavailable.
- What is signed:
  • A **SHA-256 digest** of your opaque `challenge` bytes (message_type="DIGEST").
  • Callers must ensure the challenge is unique (nonce) and bound to the operation context.
- Algorithms:
  • `ALG` is set to an RSA algorithm string. It must match the key type you provisioned in KMS.
    Common options:
      - "SHA_256_RSA_PKCS1_1_5"  (a.k.a. RSA PKCS#1 v1.5 w/ SHA-256)
      - "SHA_256_RSA_PSS"        (RSA-PSS w/ SHA-256)
    If your KMS key is RSA, either can be used (prefer PSS if policy permits).

Tunable / Config
----------------
- Region: Function takes `region`; choose the region of the Vault/key for lowest latency.
- Environment (fallback path):
  • `~/.oci/config` (standard OCI CLI config) if instance principals aren’t available.
- Endpoints:
  • Uses service endpoints:
      https://management.kms.<region>.oci.oraclecloud.com
      https://crypto.kms.<region>.oci.oraclecloud.com

Production Readiness / Improvements
-----------------------------------
- Endpoint derivation: Resolve endpoints from the **Vault OCID** to avoid region mismatch.
- Error handling: Map SDK exceptions to retryable/non-retryable classes; set timeouts and retries.
- Observability: Emit audit events containing key OCID, digest (hash only), and algorithm.
- Algorithm policy: Prefer RSA-PSS; enforce via configuration and test with negative cases.
- Digest mode: For very large inputs you already hash client-side (this module does so).

Example
-------
>>> res = kms_sign_approval(b"server-challenge", key_ocid="ocid1.key.oc1..xxx", region="us-phoenix-1")
>>> ok = verify_kms_signature(b"server-challenge", res.signature_b64, res.public_key_pem)
>>> ok
True
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Tuple

import oci
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Choose an algorithm compatible with your KMS key type.
# For RSA keys:
#   "SHA_256_RSA_PSS"          → RSA-PSS with SHA-256
#   "SHA_256_RSA_PKCS1_1_5"    → RSA PKCS#1 v1.5 with SHA-256
ALG = "SHA_256_RSA_PKCS1_1_5"  # swap to "SHA_256_RSA_PSS" if your policy prefers PSS


@dataclass
class KMSApprovalResult:
    """Return object for a KMS approval signature."""
    key_ocid: str
    signature_b64: str     # base64-encoded signature, as returned by KMS
    public_key_pem: str    # PEM-encoded public key fetched from KMS Management


def _kms_clients(region: str):
    """
    Build OCI KMS Management and Crypto clients.

    Prefers Instance Principals (on OCI/CVM) and falls back to local config.
    """
    try:
        # Best practice on OCI instances (no local API keys)
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        config = {"region": region}
    except Exception:
        # Fallback to ~/.oci/config for local/dev
        config = oci.config.from_file()
        signer = oci.signer.Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config.get("key_file"),
            pass_phrase=config.get("pass_phrase"),
        )

    kms_mgmt = oci.key_management.KmsManagementClient(
        config=config,
        signer=signer,
        service_endpoint=f"https://management.kms.{region}.oci.oraclecloud.com",
    )
    kms_crypto = oci.key_management.KmsCryptoClient(
        config=config,
        signer=signer,
        service_endpoint=f"https://crypto.kms.{region}.oci.oraclecloud.com",
    )
    return kms_mgmt, kms_crypto


def kms_sign_approval(challenge: bytes, key_ocid: str, region: str) -> KMSApprovalResult:
    """
    Ask OCI KMS (HSM) to sign a SHA-256 digest of `challenge` with the specified key.

    Args:
      challenge: Opaque bytes issued by your server (nonce + context).
      key_ocid : OCID of the KMS key to use for the approval signature.
      region   : OCI region for the KMS endpoints (e.g., "us-phoenix-1").

    Returns:
      KMSApprovalResult with:
        - key_ocid        : the OCID you passed
        - signature_b64   : base64-encoded signature string returned by KMS
        - public_key_pem  : PEM public key fetched from KMS Management (for local verify)

    Raises:
      oci.exceptions.ServiceError on KMS/API errors.
    """
    kms_mgmt, kms_crypto = _kms_clients(region)

    # Compute digest locally and sign as DIGEST to avoid double-hashing in KMS.
    digest = hashlib.sha256(challenge).digest()

    sign_details = oci.key_management.models.SignDataDetails(
        key_id=key_ocid,
        message=base64.b64encode(digest).decode("ascii"),
        signing_algorithm=ALG,
        message_type="DIGEST",
    )
    resp = kms_crypto.sign(sign_details)
    sig_b64: str = resp.data.signature  # base64 string

    # Retrieve the public key (PEM) to enable offline verification where desired.
    pub_resp = kms_mgmt.get_public_key(key_ocid)
    pub_pem: str = pub_resp.data.public_key

    return KMSApprovalResult(key_ocid=key_ocid, signature_b64=sig_b64, public_key_pem=pub_pem)


def verify_kms_signature(challenge: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """
    Verify the KMS approval signature locally using the provided public key (PEM).

    Args:
      challenge      : The original challenge bytes that were signed.
      signature_b64  : Base64-encoded signature returned by KMS.
      public_key_pem : PEM-encoded RSA public key obtained from KMS Management.

    Returns:
      True if the signature validates, False otherwise.

    Notes:
      - This function currently assumes an **RSA** key. If you switch to another key
        type (e.g., Ed25519 in the future), you must adjust verification accordingly.
      - Uses RSA PKCS#1 v1.5 / SHA-256 padding by default to match `ALG` above. If you
        use PSS in `ALG`, change the verifier padding to `padding.PSS(...)`.
    """
    pub = load_pem_public_key(public_key_pem.encode("utf-8"))
    digest = hashlib.sha256(challenge).digest()
    sig = base64.b64decode(signature_b64)

    try:
        if ALG == "SHA_256_RSA_PSS":
            pub.verify(
                sig,
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        else:
            # Default: RSA PKCS#1 v1.5
            pub.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
