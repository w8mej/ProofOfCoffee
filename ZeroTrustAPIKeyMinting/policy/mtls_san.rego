# =============================================================================
# policy/mtls_san.rego — mTLS Client SAN Pinning (documented)
#
# Purpose
# - Authorize only requests whose **peer certificate SAN** matches expected
#   service identities (e.g., coordinator ↔ signer).
#
# Security & Ops
# - Envoy must forward peer cert details (e.g., `x-forwarded-client-cert`, XFCC).
# - Deny by default; allow only SANs present in an allowlist.
#
# Tunables / Config
# - data.mtls.allowed_sans : list of permitted SAN strings (exact match) OR
#   use a regex allowlist below for namespaces/prefixes.
#
# Operational Guidance
# - Ensure Envoy is configured: `forward_client_cert_details: SANITIZE_SET` and
#   `set_current_client_cert_details: subject, cert, dns, uri`.
# - In production, prefer **SPIFFE IDs** (`spiffe://...`) and match on URI SANs.
#
# Production Considerations
# - Rotate certs frequently; SAN pinning remains stable when using SPIFFE URIs.
# - Consider also checking cert age (notBefore/notAfter) if forwarded by Envoy.
# - use SPIFFE, switch allowed_sans to URI SANs and update the parser to URI= tokens
# =============================================================================
#### Example policy/mtls.json
{ "mtls": { "allowed_sans": [
  "frost-coordinator.frost.svc",
  "frost-signer.frost.svc"
]}}
######################

package mtls_san

default allow := false

allow {
  # Example: Envoy sets input.headers["x-forwarded-client-cert"]
  xfcc := input.headers["x-forwarded-client-cert"]
  dns_sans := parse_dns_sans(xfcc)
  some s
  s := dns_sans[_]
  allowed_san(s)
}

allowed_san(s) {
  allowed := {a | a := data.mtls.allowed_sans[_]}
  allowed[s]
}

# Very simplified parser for DNS SANs from XFCC (Envoy format).
parse_dns_sans(xfcc) = sans {
  # Example XFCC: "By=spiffe://...;Hash=...;Subject=\"...\";DNS=frost-coordinator.frost.svc;DNS=frost-coordinator.frost.svc.cluster.local"
  parts := split(xfcc, ";")
  dns := [ trim(split(p, "=")[1]) | p := parts[_]; startswith(p, "DNS=") ]
  sans := dns
}

trim(s) = t {
  t := trim_prefix(trim_suffix(s, "\""), "\"")
}