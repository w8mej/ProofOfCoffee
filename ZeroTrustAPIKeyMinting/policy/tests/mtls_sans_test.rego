package mtls_san

data_allowed := {"mtls": {"allowed_sans": ["frost-coordinator.frost.svc", "frost-signer.frost.svc"]}}

# Envoy-style XFCC example
xfcc_good := "By=spiffe://cluster.local/ns/frost/sa/default;DNS=frost-coordinator.frost.svc;DNS=frost-coordinator.frost.svc.cluster.local"

test_allow_known_san {
  input := {"headers": {"x-forwarded-client-cert": xfcc_good}}
  data.mtls_san.allow with data as data_allowed with input as input
}

test_deny_unknown_san {
  xfcc := "By=spiffe://cluster.local/ns/frost/sa/default;DNS=other.svc"
  input := {"headers": {"x-forwarded-client-cert": xfcc}}
  not data.mtls_san.allow with data as data_allowed with input as input
}