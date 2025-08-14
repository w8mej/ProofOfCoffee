package jwt_claims

import future.keywords.in

# Minimal policy data for tests
testdata := {
  "jwt": {
    "allowed_algs": ["EdDSA", "RS256"],
    "allowed_issuers": ["mint-api"],
    "allowed_audiences": ["service-perimeter"],
    "max_ttl_seconds": 3600,
    "clock_skew_seconds": 120,
    "required_claims": ["sub", "scp", "role", "env", "iat", "exp"]
  }
}

# Happy path
test_allow_valid_token {
  t_iat := time.now_ns() / 1000000000
  t_exp := t_iat + 600
  input := {
    "jwt_header": {"alg": "EdDSA", "kid": "k1"},
    "jwt": {
      "iss": "mint-api",
      "aud": "service-perimeter",
      "iat": t_iat,
      "exp": t_exp,
      "sub": "alice",
      "role": "engineer",
      "env": "staging",
      "scp": ["read:test"]
    }
  }
  data.jwt_claims.allow with data as testdata with input as input
}

# Bad audience
test_deny_bad_aud {
  t := time.now_ns() / 1000000000
  input := {
    "jwt_header": {"alg": "EdDSA"},
    "jwt": {"iss": "mint-api", "aud": "wrong", "iat": t, "exp": t+60, "sub":"a","role":"r","env":"e","scp":["x"]}
  }
  not data.jwt_claims.allow with data as testdata with input as input
}

# TTL too long
test_deny_excessive_ttl {
  t := time.now_ns() / 1000000000
  input := {
    "jwt_header": {"alg": "EdDSA"},
    "jwt": {"iss": "mint-api", "aud": "service-perimeter", "iat": t, "exp": t+7200, "sub":"a","role":"r","env":"e","scp":["x"]}
  }
  not data.jwt_claims.allow with data as testdata with input as input
}