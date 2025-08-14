# policy/kms_receipt.rego
#
# ===========================
# Security & Ops
# ===========================
# - Verifies an OCI KMS co-signature (x-kms-sig) over the **JWT string** (ASCII).
# - Confirms the key identity (x-kms-key) matches an allowed list (OCIDs).
# - Parses JWT to enforce TTL (exp/iat), scope restrictions, and audience.
# - Fails CLOSED if any required input is missing or invalid.
#
# Assumptions:
# - Your mint service places headers:
#   - Authorization: Bearer <jwt>
#   - x-kms-sig: base64(signature over the JWT string, e.g., RSASSA-PSS-SHA256)
#   - x-kms-key: OCI key OCID used to generate the receipt (e.g., ocid1.key.oc1...)
# - The KMS **public key** (PEM) is shipped in the **bundle data** as `data.kms.pub_pem`
#   and allowed key OCIDs under `data.kms.allowed_keys`.
#
# ===========================
# Tunables / Config
# ===========================
# - data.kms.pub_pem          : string PEM of KMS public key (RSA PSS in this example)
# - data.kms.allowed_audiences: list of aud claims allowed
# - data.kms.allowed_scopes   : set of scopes allowed (checked as superset/overlap)
# - data.kms.max_ttl_seconds  : maximum lifetime (exp - iat) allowed
# - data.kms.allowed_keys     : list of allowed KMS key OCIDs
#
# ===========================
# Improvements / Production
# ===========================
# - Rotate/public keys via a JWKS-like doc and **pin thumbprints**.
# - Support multiple KMS keys and algorithms (RSA/ECDSA) and select dynamically by x-kms-key.
# - Cache parsed/verified JWTs using Envoy filter or OPA decision cache to reduce latency.
# - If your JWT is EdDSA, validate its signature upstream (Envoy/JWT filter or app) and let OPA
#   focus on claims + KMS receipt (this module still verifies the KMS receipt).

package kms_receipt

default allow := false

# Entry point
allow {
  # Extract headers
  hdrs := input.attributes.request.http.headers

  # Extract and normalize the Authorization header
  auth := lower(hdrs["authorization"])
  startswith(auth, "bearer ")
  token := substring(hdrs["authorization"], 7, -1)

  # Required KMS headers
  kms_sig_b64 := hdrs["x-kms-sig"]
  kms_key     := hdrs["x-kms-key"]

  # Validate the KMS key identity
  kms_key_allowed(kms_key)

  # Verify KMS signature over the JWT string (ASCII)
  valid_kms_signature(token, kms_sig_b64)

  # Decode (no signature check here) and validate claims
  claims := parse_jwt(token)

  # TTL (exp - iat) must be bounded
  ttl_ok(claims)

  # Enforce audience and scopes
  audience_ok(claims)
  scopes_ok(claims)
}

################################################################################
# Helpers
################################################################################

kms_key_allowed(k) {
  allowed := data.kms.allowed_keys
  k != null
  allowed[_] == k
}

# Verifies x-kms-sig (base64) over the JWT ASCII string using RSA-PSS-SHA256.
# If your OCI KMS key is ECDSA, switch to crypto.verify_ecdsa_sha256.
valid_kms_signature(jwt_str, sig_b64) {
  pub_pem := data.kms.pub_pem
  sig := base64.decode(sig_b64)

  # crypto.verify_rsassa_pss_sha256(public_key_pem, message, signature)
  crypto.verify_rsassa_pss_sha256(pub_pem, jwt_str, sig)
}

# Parse JWT without verifying the primary signature (EdDSA/RSA/etc.). We rely on the
# application or an upstream Envoy JWT filter for primary signature verification.
parse_jwt(token) = claims {
  [header, payload, _] := io.jwt.decode(token)
  # Optionally enforce alg/kid from header: e.g., header.alg == "EdDSA"
  claims := payload
}

ttl_ok(claims) {
  max := to_number(data.kms.max_ttl_seconds)
  iat := to_number(claims.iat)
  exp := to_number(claims.exp)
  exp > time.now_ns() / 1000000000  # token not expired at decision time
  (exp - iat) <= max
}

audience_ok(claims) {
  allowed := {a | a := data.kms.allowed_audiences[_]}
  some a
  a := claims.aud
  a != null
  allowed[a]
}

scopes_ok(claims) {
  # Example: "scp" claim is list of scopes. Adjust to your claim name.
  allowed := {s | s := data.kms.allowed_scopes[_]}
  requested := claims.scp
  count(requested) > 0

  # All requested scopes must be allowed (change to overlap check if desired)
  not disallowed_scope(allowed, requested)
}

disallowed_scope(allowed, requested) {
  some s
  s := requested[_]
  not allowed[s]
}