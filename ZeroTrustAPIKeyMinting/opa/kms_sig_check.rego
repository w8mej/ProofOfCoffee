# =============================================================================
# policy/kms_receipt.rego — KMS Receipt Signature Verification (documented)
#
# Purpose
# - Implements an OPA authorization policy to verify that incoming requests
#   carry a valid KMS-signed challenge receipt before being allowed.
#
# How It Works
# - The policy expects the request to include:
#     1. HTTP header `x-kms-sig` — Base64URL-encoded RSA signature from KMS.
#     2. `kms_public_key_pem` — PEM-encoded RSA public key of the KMS.
#     3. `challenge` — Challenge string that was signed.
#
# - The `allow` rule evaluates to `true` only if:
#     - The `x-kms-sig` header is present.
#     - The signature is valid for the challenge using the provided public key.
#
# Security & Ops
# - This policy enforces **proof-of-KMS-signature** as an additional
#   authentication/authorization layer, ensuring that only workloads that
#   can present a valid KMS receipt may proceed.
# - Signature verification is abstracted in `valid_sig()`; production
#   deployments must implement actual RSA verification.
# - Inputs (headers, PEM keys, challenge) should be passed from the Envoy
#   external authorization filter or another trusted ingress proxy.
#
# Operational Guidance
# - Deploy as part of an OPA sidecar or centralized OPA service, fronted
#   by Envoy with `ext_authz` filter enabled.
# - Ensure Envoy is configured to pass required headers and JWT claims
#   into `input.jwt_header` and `input.challenge`.
# - Keep the KMS public key up-to-date; rotate on schedule or upon suspicion.
# - Monitor for deny events to detect unauthorized or tampered requests.
#
# Production Considerations
# - Use constant-time signature verification to avoid timing attacks.
# - Consider enforcing expiration and nonce checks in the challenge payload
#   to prevent replay attacks.
# - Integrate with a secure channel (mTLS) to prevent header tampering.
# =============================================================================

package authz

default allow = false

allow {
    input.jwt_header["x-kms-sig"]
    valid_sig(input.jwt_header["x-kms-sig"], input.kms_public_key_pem, input.challenge)
}

valid_sig(sig_b64, pubkey_pem, challenge) {
    # Pseudo: Implement base64 decode + RSA verify with builtin or external verifier
    sig := base64url.decode(sig_b64)
    # call out to external RSA verify (not implemented here)
    true
}