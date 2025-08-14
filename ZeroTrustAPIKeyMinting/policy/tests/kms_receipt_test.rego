package authz

# NOTE: valid_sig() is a stub in the PoC; we simulate "true" here by
# setting a header and challenge. In production, implement actual RSA verify.

test_allow_when_header_present_and_stub_verify {
  input := {
    "jwt_header": {"x-kms-sig": "dummy"},
    "kms_public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----",
    "challenge": "C1"
  }
  allow with input as input
}

test_deny_when_header_missing {
  input := {"jwt_header": {}, "kms_public_key_pem": "k", "challenge": "C1"}
  not allow with input as input
}