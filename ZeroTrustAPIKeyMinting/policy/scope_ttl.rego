 =============================================================================
# policy/scope_ttl.rego — Scope/TTL Enforcement (documented)
#
# Purpose
# - Enforce that requested scopes (scp) and token TTL respect a per-role/per-env
#   policy loaded from bundle data.
#
# Security & Ops
# - Denies scope elevation attempts and overly long TTLs even if JWT was issued.
# - Aligns token power with least privilege and environment segregation.
#
# Tunables / Config (data.policy.*)
# - roles: { "engineer": {"max_ttl_seconds": 1800, "allow_scopes": ["read:test", ...]}, ... }
# - envs : { "prod": {"deny_scopes": ["write:prod-admin"]}, ... } (optional overlays)
#
# Operational Guidance
# - Ensure JWT includes `role`, `env`, and `scp` claims.
# - Keep policy in a signed bundle and version it; add CI tests for negative/positive cases.
#
# Production Considerations
# - Add ABAC inputs (change window, ticket id) and bind to `scp` via policy.
# - Emit deny reason to logs for forensics; avoid leaking sensitive policy internals.
# =============================================================================
##### Example policy/data.json
#{
#  "policy": {
#    "roles": {
#      "engineer": {
#        "max_ttl_seconds": 1800,
#        "allow_scopes": ["read:test", "write:test", "read:staging"]
#      },
#      "sre": {
#        "max_ttl_seconds": 3600,
#        "allow_scopes": ["read:*", "write:staging"]
#      }
#    },
#    "envs": {
#      "prod": { "deny_scopes": ["write:prod-admin"] }
#    }
#  }
#}
####################

package scope_ttl

default allow := false

allow {
  role := input.jwt.role
  env  := input.jwt.env
  scps := input.jwt.scp

  # TTL within role cap
  ttl_within_cap(role)

  # All requested scopes allowed by role and not denied by env
  all_scopes_allowed(role, env, scps)
}

ttl_within_cap(role) {
  max := to_number(data.policy.roles[role].max_ttl_seconds)
  exp := to_number(input.jwt.exp)
  iat := to_number(input.jwt.iat)
  exp - iat <= max
}

all_scopes_allowed(role, env, scps) {
  allowed := {s | s := data.policy.roles[role].allow_scopes[_]}
  denied  := {s | s := data.policy.envs[env].deny_scopes[_]}  # may be undefined

  not any_denied(denied, scps)
  subset(scps, allowed)
}

any_denied(denied, scps) {
  some s
  s := scps[_]
  denied[s]
}

subset(xs, ys) {
  not exists_not_in(xs, ys)
}

exists_not_in(xs, ys) {
  some x
  x := xs[_]
  not ys[x]
}