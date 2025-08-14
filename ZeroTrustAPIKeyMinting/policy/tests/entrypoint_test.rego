package entrypoint

# Compose: we treat sub-policies as already tested; here we validate wiring.
test_compose_allows_when_all_true {
  # Stubbing sub-policy allows:
  allow with data as {
    "jwt_claims": {"allow": true},
    "scope_ttl":  {"allow": true},
    "mtls_san":   {"allow": true},
    "sev_snp":    {"allow": true},
    "authz":      {"allow": true}
  }
}

test_compose_denies_when_any_false {
  not allow with data as {
    "jwt_claims": {"allow": true},
    "scope_ttl":  {"allow": true},
    "mtls_san":   {"allow": false},
    "sev_snp":    {"allow": true},
    "authz":      {"allow": true}
  }
}