# policy/entrypoint.rego
package entrypoint

default allow := false

# Default deny unless it is allowed below
allow {
  jwt_claims.allow
  scope_ttl.allow
  mtls_san.allow
  sev_snp.allow
  kms_receipt.allow  # from your existing module
  data.authz.allow
}
