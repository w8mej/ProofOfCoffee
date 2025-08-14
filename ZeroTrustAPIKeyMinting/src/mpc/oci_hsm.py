"""
oci_hsm.py — OCI KMS (HSM) co-signing helper (documented)

Security & Ops
--------------
Purpose:
  Produce an HSM-backed signature (via **OCI Key Management / Vault**) over a message,
  typically the JWT `signing_input` ("base64url(header).base64url(payload)") or a mint
  receipt blob. The returned signature can be embedded in the JWT header as `x-kms-sig`
  (and `x-kms-key` for the OCID) so downstream verifiers/OPA can enforce a **co-sign**
  policy.

Trust boundaries:
  • Private keys never leave OCI KMS HSMs.
  • This module only calls the KMS **Crypto** endpoint; it does not manage key lifecycle.

Important compatibility notes:
  • OCI KMS expects the request `message` to be **base64-encoded** when `message_type="RAW"`.
  • The returned `signature` is **base64-encoded**; callers often want raw bytes.
  • The **signing algorithm must match the key type** you provisioned:
      - For RSA keys (e.g., your Terraform uses RSA 2048): "RSA_PSS_SHA_256" (recommended)
        or "RSA_PKCS1_SHA_256".
      - If/when Ed25519 is supported for your tenancy, it would be "EDDSA_ED25519".
    Passing an algorithm that doesn't match the key will yield a server error.

Tunable / Config
----------------
Environment variables:
  • OCI_CONFIG_FILE            : Path to OCI CLI config (default: "~/.oci/config")
  • OCI_PROFILE                : Profile name within the config (default: "DEFAULT")
  • OCI_KMS_CRYPTO_ENDPOINT    : **Crypto endpoint** for the target Vault (required).
                                 Example: "https://<vault-ocid>-crypto.kms.<region>.oraclecloud.com"
Function parameters:
  • vault_key_ocid (str)       : OCID of the KMS Key to use for signing.
  • message (bytes)            : The raw bytes to sign (this function will base64-encode).
  • algorithm (str)            : One of OCI-supported algorithms (see above). Defaults to
                                 "RSA_PSS_SHA_256" to align with the RSA-2048 key in Terraform.

Production Readiness / Improvements
-----------------------------------
- Endpoint resolution: Look up the proper **crypto endpoint** from the Vault OCID dynamically
  (ListVaults / GetVault). Here we rely on the `OCI_KMS_CRYPTO_ENDPOINT` env var for simplicity.
- Error handling: Catch SDK errors and map to structured, retryable categories (throttling, 5xx).
- Auditing: Emit an event (key OCID, algorithm, digest of message) to your append-only audit log.
- Timeouts/retries: Configure the underlying SDK with sensible timeouts and retry policies.
- Digest mode: For very large payloads, compute a local digest and call KMS with message_type="DIGEST".

Example
-------
>>> sig_b = oci_hsm_sign(vault_key_ocid="ocid1.key.oc1..xxx", message=b"abc")
>>> # base64url-encode sig_b and place into JWT header as x-kms-sig
"""

from __future__ import annotations

import base64
import os
from typing import Dict, Any

from oci import config as oci_config
from oci import key_management
from oci.key_management.models import SignDataDetails


def load_oci_config() -> Dict[str, Any]:
    """
    Load OCI SDK configuration from a CLI-compatible config file.

    Returns:
      Dict suitable for OCI Python SDK clients.

    Env:
      OCI_CONFIG_FILE (default "~/.oci/config")
      OCI_PROFILE     (default "DEFAULT")
    """
    oci_config_path = os.getenv("OCI_CONFIG_FILE", "~/.oci/config")
    oci_profile = os.getenv("OCI_PROFILE", "DEFAULT")
    return oci_config.from_file(
        file_location=os.path.expanduser(oci_config_path),
        profile_name=oci_profile,
    )


def oci_hsm_sign(
    vault_key_ocid: str,
    message: bytes,
    *,
    algorithm: str = "RSA_PSS_SHA_256",
) -> bytes:
    """
    Request an HSM-backed signature from OCI KMS over `message`.

    Args:
      vault_key_ocid: OCID of the KMS key to use.
      message: Raw message bytes (this function base64-encodes them for KMS).
      algorithm: OCI KMS signing algorithm string. For RSA-2048 keys from Terraform,
                 prefer "RSA_PSS_SHA_256". Use "RSA_PKCS1_SHA_256" if policy requires.

    Returns:
      Raw signature bytes (decoded from the base64 string returned by OCI KMS).

    Raises:
      ValueError if required environment variables are missing.
      oci.exceptions.ServiceError for KMS/API errors.
    """
    # KMS Crypto client requires the **Crypto** endpoint for the specific Vault.
    crypto_endpoint = os.getenv("OCI_KMS_CRYPTO_ENDPOINT")
    if not crypto_endpoint:
        raise ValueError(
            "OCI_KMS_CRYPTO_ENDPOINT is required (KMS crypto endpoint URL)")

    conf = load_oci_config()
    kms_crypto_client = key_management.KmsCryptoClient(
        config=conf,
        service_endpoint=crypto_endpoint,
    )

    # Per OCI API, message must be base64-encoded when message_type="RAW".
    details = SignDataDetails(
        key_id=vault_key_ocid,
        signing_algorithm=algorithm,
        message=base64.b64encode(message).decode("ascii"),
        message_type="RAW",
    )

    # Perform the signing operation.
    resp = kms_crypto_client.sign(details)

    # OCI returns a base64-encoded signature string; decode to raw bytes for callers.
    sig_b64 = resp.data.signature  # type: ignore[attr-defined]
    if not isinstance(sig_b64, str):
        # Defensive: some SDK versions may return bytes; normalize to str first.
        sig_b64 = sig_b64.decode("ascii")
    return base64.b64decode(sig_b64)
