# Handler.py
# -----------------------------------------------------------------------------
# Purpose:
#   Enforce that this function only runs when invoked by a deployment whose
#   Terraform plan fingerprint matches a certificate bound to that deployment.
#
# Threat Model (high level):
#   - CI/CD generates a plan and computes its SHA-256 fingerprint.
#   - Vault/PKI issues a short-lived TLS cert *tied to that fingerprint*.
#   - The invoker must present the plan fingerprint (header) and the function
#     must verify it against the cert (from env) before executing.
#
# Notes:
#   - This PoC uses the cert serial number as the binding for simplicity.
#   - In production, prefer a custom X.509 extension (OID) carrying the
#     plan fingerprint + validate the cert chain + expiry.
# -----------------------------------------------------------------------------

"""
Implementation notes for a real deployment (kept out of code to stay minimal):
	•	Replace serial-number binding with a custom X.509 extension carrying the exact plan SHA‑256 (hex).
	•	Perform full certificate chain validation and TTL checks (NotBefore/NotAfter).
	•	Use hmac.compare_digest for the fingerprint comparison.
	•	Bounded header size & input validation; log rejections centrally.
	•	Rotate and revoke certs per deployment; keep TTLs short (minutes).
"""


import os
# (unused here; retained to show intent for real fingerprinting)
import hashlib
import base64   # (unused here; retained for future header/cert transport)
import ssl      # (unused; would be used for chain/hostname validation)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def handler(ctx, data: bytes = None):
    """
    Entry point for the function runtime.

    Args:
        ctx:   Platform-provided context with request metadata (headers, etc.)
        data:  Raw request body (unused in this PoC)

    Returns:
        dict: JSON-safe structure on success.

    Raises:
        Exception: If the certificate is missing/invalid, header absent, or
                   the fingerprint does not match (unauthorized invocation).
    """

    # 1) Load the deployment-scoped TLS certificate from environment.
    #    The platform/CI injects TLS_CERT (PEM) for this function version.
    cert_pem = os.getenv("TLS_CERT")
    if not cert_pem:
        # Prod: prefer structured 401/403 response and central logging.
        raise Exception("Missing TLS_CERT environment variable")

    # Parse the PEM-encoded certificate so we can inspect its fields.
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # 2) Retrieve the plan fingerprint the caller must provide.
    #    CI/CD sets header `X-Plan-Fingerprint: <hex digest>` at invocation.
    plan_fingerprint = ctx.request_headers.get("X-Plan-Fingerprint")
    if not plan_fingerprint:
        raise Exception("Missing plan fingerprint")

    # 3) Authorization check: compare caller’s fingerprint to the binding in
    #    the cert. This PoC uses the serial number as the binding. For real
    #    deployments, store the fingerprint in a custom extension (OID) and
    #    validate:
    #      - Certificate chain to the issuing CA
    #      - NotBefore/NotAfter (TTL)
    #      - Key usage / Extended Key Usage
    #
    # Convert the cert serial to fixed-size big-endian hex so formats match.
    cert_fingerprint_hex = cert.serial_number.to_bytes(8, "big").hex()

    # Prod: use hmac.compare_digest for constant-time compare to reduce
    # timing side-channels (here it’s a simple string compare for clarity).
    if plan_fingerprint != cert_fingerprint_hex:
        raise Exception("Plan fingerprint mismatch – unauthorized deployment")

    # If we get here, the invocation is authorized for this exact plan.
    return {"message": "Function invoked with valid plan!"}
