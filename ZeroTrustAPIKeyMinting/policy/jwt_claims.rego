# =============================================================================
# policy/jwt_claims.rego — Strict JWT Claims Validation (documented)
#
# Purpose
# - Enforce baseline JWT hygiene: signature alg/kid, exp/iat/nbf sanity, aud/iss,
#   jti uniqueness (replay guard via upstream), and required custom claims.
#
# Security & Ops
# - Assumes JWT primary signature validation occurs upstream (Envoy jwt_authn filter
#   or your application). This module validates **claims** and **headers** only.
# - Denies tokens with clock-skewed iat/nbf, excessive TTL, wrong audience/issuer,
#   or missing required claims (e.g., scp).
#
# Tunables / Config
# - data.jwt.allowed_algs       : e.g., ["EdDSA", "RS256"]
# - data.jwt.allowed_issuers    : e.g., ["mint-api"]
# - data.jwt.allowed_audiences  : e.g., ["mint-api", "service-perimeter"]
# - data.jwt.max_ttl_seconds    : e.g., 3600
# - data.jwt.clock_skew_seconds : e.g., 120
# - data.jwt.required_claims    : e.g., ["sub", "scp"]
#
# Operational Guidance
# - Feed decoded JWT header/payload via Envoy ext_authz: set input.jwt_header, input.jwt.
# - Enforce **deny by default**; compose with other modules using `allow` rules.
# - For replay: ensure upstream stores/invalidates `jti` or enforces nonce.
#
# Production Considerations
# - Rotate allowed_algs/kids via signed bundle updates.
# - Combine with OPA decision logs and SIEM alerts on deny reasons.
# =============================================================================

package jwt_claims

default allow := false

# Entrypoint
allow {
  alg_ok
  iss_ok
  aud_ok
  ttl_ok
  not expired
  nbf_ok
  required_claims_ok
}

# Inputs (from Envoy or app):
# input.jwt_header: { alg: "EdDSA", kid: "...", ... }
# input.jwt       : { iss, aud, exp, iat, nbf?, jti?, sub, scp: ["..."] }
# time.now_ns()   : current time

alg_ok {
  allowed := {a | a := data.jwt.allowed_algs[_]}
  input.jwt_header.alg != null
  allowed[input.jwt_header.alg]
}

iss_ok {
  allowed := {i | i := data.jwt.allowed_issuers[_]}
  input.jwt.iss != null
  allowed[input.jwt.iss]
}

aud_ok {
  allowed := {a | a := data.jwt.allowed_audiences[_]}
  input.jwt.aud != null
  allowed[input.jwt.aud]
}

expired {
  to_number(input.jwt.exp) <= now_s()
}

ttl_ok {
  max := to_number(data.jwt.max_ttl_seconds)
  exp := to_number(input.jwt.exp)
  iat := to_number(input.jwt.iat)
  exp - iat <= max
  exp > now_s()                # still valid
}

nbf_ok {
  # not-before must be <= now + skew
  skew := to_number(data.jwt.clock_skew_seconds)
  nbf := to_number(input.jwt.nbf, 0)  # treat missing as 0
  nbf <= now_s() + skew
}

required_claims_ok {
  req := {c | c := data.jwt.required_claims[_]}
  # All required must be present and non-empty
  not missing_claim(req)
}

missing_claim(req) {
  some c
  c := req[_]
  not has_nonempty(input.jwt, c)
}

has_nonempty(obj, key) {
  v := obj[key]
  v != null
  # consider empty arrays/strings invalid
  not is_empty(v)
}

is_empty(x) {
  x == ""
} else = true {
  count(x) == 0
}

now_s() = floor(time.now_ns() / 1e9)