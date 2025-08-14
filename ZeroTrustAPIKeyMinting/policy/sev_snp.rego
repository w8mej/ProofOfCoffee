# =============================================================================
# policy/sev_snp.rego — AMD SEV-SNP Attestation Enforcement (documented)
#
# Purpose
# - Allow only requests that present a verified SEV-SNP report **bound to a server
#   challenge nonce**, and whose measurement & policy match approved values.
#
# Security & Ops
# - Assumes an upstream verifier (mint API or Envoy filter) has validated the
#   SNP *certificate chain* and *signature* and passes results to OPA:
#     input.snp.verified         : boolean
#     input.snp.nonce            : hex/base64 nonce
#     input.snp.measurement      : hex hash of the image/boot state
#     input.snp.policy_hash      : hex hash of the enforced policy/config
#     input.challenge            : challenge string the server issued
#
# - OPA checks:
#     1) verified == true
#     2) nonce == hash(challenge) or exact challenge per your binding scheme
#     3) measurement in allowlist
#     4) policy_hash in allowlist
#
# Tunables / Config
# - data.snp.allowed_measurements : set of approved measurements (per image version)
# - data.snp.allowed_policies     : set of approved policy hashes
# - data.snp.nonce_binding        : "raw" | "sha256" (how the server hashes challenge into report nonce)
#
# Operational Guidance
# - Rotate allowlists on image updates; publish via signed OPA bundles.
# - Emit decision logs for denials with reason codes (non-sensitive).
#
# Production Considerations
# - Block on any `verified=false` regardless of other matches.
# - Consider binding additional context (cluster, pod UID) into the nonce or policy.
# =============================================================================
##### Example policy/snp.json
#{
#  "snp": {
#    "nonce_binding": "sha256",
#    "allowed_measurements": ["abc123...deadbeef", "f00ba7...42"],
#    "allowed_policies": ["9d9c...001", "77aa...ef5"]
#  }
#}
######################

package sev_snp

default allow := false

allow {
  input.snp.verified == true
  nonce_ok
  measurement_ok
  policy_ok
}

nonce_ok {
  mode := data.snp.nonce_binding
  mode == "raw"
  input.snp.nonce == input.challenge
} else {
  mode := data.snp.nonce_binding
  mode == "sha256"
  input.snp.nonce == hex_sha256(input.challenge)
}

measurement_ok {
  allowed := {m | m := data.snp.allowed_measurements[_]}
  allowed[input.snp.measurement]
}

policy_ok {
  allowed := {p | p := data.snp.allowed_policies[_]}
  allowed[input.snp.policy_hash]
}

# Simple SHA256 hex helper (OPA v0.62+ has crypto helpers; use accordingly)
hex_sha256(x) = h {
  bs := to_numberset(sha256(x))
  h  := lower(sprintf("%x", [bs]))
}