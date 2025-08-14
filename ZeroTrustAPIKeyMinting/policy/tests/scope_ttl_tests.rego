package scope_ttl

policy := {
  "roles": {
    "engineer": {"max_ttl_seconds": 1800, "allow_scopes": ["read:test", "write:test", "read:staging"]},
    "sre":      {"max_ttl_seconds": 3600, "allow_scopes": ["read:*", "write:staging"]}
  },
  "envs": {
    "prod": {"deny_scopes": ["write:prod-admin"]}
  }
}

test_engineer_ok {
  t := time.now_ns()/1000000000
  input := {"jwt": {
    "role": "engineer", "env": "staging",
    "scp": ["read:test", "write:test"],
    "iat": t, "exp": t+600
  }}
  data.scope_ttl.allow with data.policy as policy with input as input
}

test_deny_scope_elevation {
  t := time.now_ns()/1000000000
  input := {"jwt": {
    "role": "engineer", "env": "staging",
    "scp": ["write:prod-admin"],  # not allowed
    "iat": t, "exp": t+600
  }}
  not data.scope_ttl.allow with data.policy as policy with input as input
}

test_deny_ttl {
  t := time.now_ns()/1000000000
  input := {"jwt": {
    "role": "engineer", "env": "staging",
    "scp": ["read:test"],
    "iat": t, "exp": t+7200  # exceeds role cap
  }}
  not data.scope_ttl.allow with data.policy as policy with input as input
}