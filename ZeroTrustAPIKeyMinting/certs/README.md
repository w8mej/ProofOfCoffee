# certs/README.md

Place your **trusted attestation roots** and mTLS materials here.

---

## YubiKey PIV Attestation

For **YubiKey PIV attestation**, add the **Yubico PIV Attestation** root CA certificate:

- Suggested filename: `yubico-piv-attestation-ca.pem`

---

## WebAuthn (FIDO2)

Maintain a Metadata Service (MDS) feed or a curated local trust store of **AAGUID → AA roots**.

- In this PoC, **registration** does *not* validate against MDS. **Assertion** is verified against the stored credential public key.
- If you want MDS validation, place the relevant AA root CAs in this folder and point the server to them (see **Tunables** below).

---

## SEV-SNP Attestation

Place the **AMD** chain here if you are doing offline verification:

- `amd-ark.pem`
- `amd-ask.pem`
- Per-CPU **VCEK** (or provide the AMD URL for on-demand fetch in config).

---

## OCI KMS Co-sign Receipts

Place optional **public key** material here if you are not resolving it via OCI APIs at runtime.

---

## Suggested Directory Layout

```
certs/
├── piv/
│   └── yubico-piv-attestation-ca.pem
├── webauthn/
│   ├── aa-roots/       # Optional per-AAGUID roots (if bypassing MDS)
│   └── mds-cache.json  # Optional cached MDS metadata
├── snp/
│   ├── amd-ark.pem
│   ├── amd-ask.pem
│   └── vcek/           # Optional per-CPU VCEKs, if pre-fetched
├── mtls/
│   ├── ca.crt          # Cluster-wide CA (cert-manager or external)
│   ├── server.crt
│   ├── server.key
│   └── client/         # Optional separate client chain
└── kms/
    └── oci-kms-pub.pem # Optional static KMS public key (normally fetched)
```

> In Kubernetes, these are usually projected via `Secret` or cert-manager-managed `Certificate` resources. For local Docker/dev, the API reads from this folder.

---

## Usage in PoC

- **PIV/WebAuthn Attestation**
  - Registration stores the credential’s public key.
  - Assertion verifies signatures using the stored key and enforces **replay protection** (challenge + `sign_count`).
  - If `PIV_ATTEST_ROOTS` or `WEBAUTHN_AA_ROOTS_DIR` are set, the server verifies certificate chains against the provided roots.

- **SEV-SNP**
  - Verifies SNP report and binds `/mint` challenge to **report nonce**.
  - If `SNP_OFFLINE_ROOTS_DIR` is set, AMD chain is loaded locally; otherwise can be fetched online.
  - Measurements/policy are pinned via `SNP_ALLOWED_MEASUREMENTS` and `SNP_POLICY_HASH`.

- **mTLS (FROST RPC)**
  - Signer ↔ Coordinator traffic uses **mTLS + JWT**.
  - In Kubernetes, cert-manager issues `frost-tls`; in local/dev, drop PEMs into `certs/mtls/`.

- **OCI KMS Co-sign Receipt**
  - API adds `x-kms-sig` / `x-kms-key` to JWT header.
  - Verifiers check using OCI-fetched or locally provided key.

---

## Security & Ops Guidelines

- **Trust Store Hygiene**
  - Verify CA/chain file integrity via SHA-256 checksums; record in version control (never commit private keys).
  - Permissions: public certs `0644`, private keys `0600` owned by service user.

- **Rotation**
  - Use cert-manager renewal windows (e.g., 15 days before expiry).
  - Refresh MDS metadata if validating authenticators.

- **Provenance**
  - Document source, URL, retrieval time for each root.
  - Prefer official vendor sources.

- **Least Privilege**
  - Namespace-scoped secrets for mTLS/JWT keys.
  - Restrict RPC traffic via NetworkPolicies.

- **Observability**
  - Monitor `/metrics` for cert expiry, failed validations, unusual rejection spikes.

---

## Tunables / Config

- **PIV/WebAuthn**
  - `PIV_ATTEST_ROOTS`
  - `WEBAUTHN_AA_ROOTS_DIR`
  - `MDS_URL`
  - `WEBAUTHN_RP_ID`
  - `WEBAUTHN_ORIGIN`

- **SEV-SNP**
  - `SNP_REQUIRED`
  - `SNP_OFFLINE_ROOTS_DIR`
  - `SNP_ALLOWED_MEASUREMENTS`
  - `SNP_POLICY_HASH`

- **mTLS/FROST**
  - `TLS_CERT_PEM`, `TLS_KEY_PEM`, `TLS_CLIENT_CA`
  - `JWT_HS256_B64_FILE`

- **KMS Receipt**
  - `KMS_KEY_OCID`
  - `KMS_PUBLIC_PEM`
  - `KMS_VERIFY_STRICT`

- **General**
  - `TRUST_BUNDLE_DIR`
  - `TRUST_BUNDLE_REFRESH_SECONDS`

---

## Operational Tips

- Stage updates in `certs/_staging` before swapping.
- Allow blue/green roots during rotations.
- Detect drift by hashing the `certs/` tree.

---

## Improvements / Next Steps

- Full WebAuthn MDS validation at registration.
- Pinning by model/family.
- SNP VCEK freshness proof.
- Auto-resolve KMS public keys.
- Sign trust bundle with internal CA/Sigstore.

---

## Production Hardening

- Authoritative trust bundle repo with review gates.
- Enforce attestation at all hops.
- Rotation SLAs and alarms.
- Separate roots for server/client auth.
- Source secrets from OCI Vault.
- Persist validation logs for compliance.

---

## Verification Snippets

**PIV Attestation:**
```bash
openssl verify -CAfile certs/piv/yubico-piv-attestation-ca.pem device_attestation.pem
```

**AMD SNP Chain:**
```bash
openssl verify -CAfile certs/snp/amd-ark.pem -untrusted certs/snp/amd-ask.pem vcek_cert.pem
```

**Check mTLS Cert Expiry:**
```bash
openssl x509 -enddate -noout -in certs/mtls/server.crt
```
