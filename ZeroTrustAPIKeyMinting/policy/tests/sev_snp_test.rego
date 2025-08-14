package sev_snp

data_snp := {
  "snp": {
    "nonce_binding": "raw",
    "allowed_measurements": ["abc123"],
    "allowed_policies": ["deadbeef"]
  }
}

test_allow_verified_raw_nonce {
  input := {"snp": {"verified": true, "nonce": "N1", "measurement": "abc123", "policy_hash": "deadbeef"}, "challenge": "N1"}
  data.sev_snp.allow with data as data_snp with input as input
}

test_deny_unverified {
  input := {"snp": {"verified": false, "nonce": "N1", "measurement": "abc123", "policy_hash": "deadbeef"}, "challenge": "N1"}
  not data.sev_snp.allow with data as data_snp with input as input
}

test_deny_bad_meas {
  input := {"snp": {"verified": true, "nonce": "N1", "measurement": "zzz", "policy_hash": "deadbeef"}, "challenge": "N1"}
  not data.sev_snp.allow with data as data_snp with input as input
}