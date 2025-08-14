# OPA Policy Bundle — Build & CI Guide

This directory contains the Rego policies and data used to enforce:
- JWT hygiene (alg/iss/aud/ttl/required claims),
- Scope/TTL enforcement by role/env,
- mTLS SAN pinning (or SPIFFE URIs),
- SEV-SNP attestation gating (nonce/measurement/policy),
- KMS co-signature receipt checks.

The bundle is built and tested locally with `opa`, and in CI via GitHub Actions.

---

## Quick Start

```bash
# Format and test policies
opa fmt -w policy/
opa test -v policy/

# Build a versioned bundle (tar.gz)
opa build policy/ -o policy/bundle/policy.tar.gz

The resulting artifact policy/bundle/policy.tar.gz can be served to OPA sidecars or a central OPA via the Bundle API, or mounted directly into the container image.


## Deploying the Bundle to OPA

### Option A — Sidecar with Mounted Bundle
- Bake `policy/bundle/policy.tar.gz` into your container image or mount via ConfigMap/volume.
- Start OPA with:
```bash
opa run --server     --set=plugins.envoy_ext_authz_grpc.addr=:9191     --set=plugins.envoy_ext_authz_grpc.query=data.entrypoint.allow     policy/bundle/policy.tar.gz
```

---

### Option B — Remote Bundle Server (Recommended)
- Host the tarball behind HTTPS (OCI Object Storage pre-authenticated URL or internal service).
- Example OPA config (`opa-config.yaml`):
```yaml
services:
  bundlesvc:
    url: https://bundles.internal.example.com
bundles:
  secure:
    service: bundlesvc
    resource: /policy.tar.gz
    persist: true
    polling:
      min_delay_seconds: 60
      max_delay_seconds: 300
plugins:
  envoy_ext_authz_grpc:
    addr: :9191
    query: data.entrypoint.allow
```

---

## Improvements & Production Readiness
- **Bundle signing** — Sign `policy.tar.gz` and verify signature/digest before OPA loads it.
- **Per-route policies** — Use Envoy `typed_per_filter_config` to target different OPA queries per path/service (e.g., stricter checks on `/mint`).
- **Policy A/B tests** — Maintain stable and canary bundles; gradually shift traffic via Envoy routes to validate new rules.
- **OPA HA** — Run OPA as a Deployment with multiple replicas; enable Envoy retry/backoff for `ext_authz`.
- **Performance** — Use partial evaluation (`opa build -t wasm`) if embedding policies at the edge and ultra-low latency is required.
- **Observability** — Export OPA decision logs/metrics; alert on deny spikes or policy loading errors.

---

## Troubleshooting
- **Policy compile/test failures** — Run:
```bash
opa eval -i input.json -d policy/ 'data.entrypoint.allow'
```
  to inspect decisions with a captured input.
- **Header/claim wiring** — Verify Envoy is forwarding the expected fields; dump input with a temporary policy that logs input keys.
- **Unexpected denies** — Check allowlists in `policy/data/*.json` (SANs, measurements, scopes) and token TTL calculations.

---

## References
- [OPA Bundle docs](https://www.openpolicyagent.org/docs/latest/management-bundles/)
- [Envoy ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter)
- [OPA Envoy plugin](https://www.openpolicyagent.org/docs/latest/envoy-introduction/)