# Dockerfile.md — Build, Scan, and Deploy Guide (PoC)

> **Status:** Proof of Concept (PoC) — not production-ready. This document explains how to build, scan, and deploy the credential-rotation container image to **AWS ECR** and **OCI OCIR**, aligned with the provided Makefile and CI workflow.

---

## 1) Build Locally (single image for both clouds)

The image targets `linux/amd64` to match Lambda/OCI Functions defaults.

```bash
# From repo root
make build   IMAGE_NAME=rotator   IMAGE_TAG=$(git rev-parse --short=12 HEAD)   CONTEXT_DIR=infra/shared/image
```

**Why**: One image keeps your supply chain simple and ensures parity between AWS and OCI execution environments.

---

## 2) Optional: Generate SBOM (PoC hook)

```bash
# Requires syft (https://github.com/anchore/syft)
make sbom IMAGE_NAME=rotator IMAGE_TAG=$(git rev-parse --short=12 HEAD)
# Output: sbom-rotator-<tag>.spdx.json
```

**Production**: Publish SBOM as artifact; verify on pull/deploy. Add license policy checks as needed.

---

## 3) Optional: Vulnerability Scan (PoC hook)

```bash
# Requires trivy (https://github.com/aquasecurity/trivy)
make scan IMAGE_NAME=rotator IMAGE_TAG=$(git rev-parse --short=12 HEAD)
```

**Production**: Fail the pipeline on HIGH/CRITICAL findings; maintain an allowlist for false positives with expiry.

---

## 4) Optional: Sign the Image (PoC hook)

```bash
# Requires cosign (https://github.com/sigstore/cosign)
export COSIGN_EXPERIMENTAL=1
make sign IMAGE_NAME=rotator IMAGE_TAG=$(git rev-parse --short=12 HEAD)   AWS_REGION=us-west-2 AWS_ACCOUNT_ID=123456789012   OCIR_REGION=phx OCIR_NS=mytenancy
```

**Production**: Enforce signature verification on pull (ECR/OCIR policies or admission controls). Prefer **digest pinning** in Terraform/Function configs.

---

## 5) Push to AWS ECR

```bash
# Login and create repo if needed, then push
make push-ecr   AWS_REGION=us-west-2   AWS_ACCOUNT_ID=123456789012   ECR_REPO=rotator   IMAGE_NAME=rotator   IMAGE_TAG=$(git rev-parse --short=12 HEAD)
```

Resulting image URI:
```
123456789012.dkr.ecr.us-west-2.amazonaws.com/rotator:<gitsha>
```

**Tip**: Record the **digest** and use it in IaC for immutability:
```bash
DIGEST=$(aws ecr describe-images   --repository-name rotator   --image-ids imageTag=$(git rev-parse --short=12 HEAD)   --query 'imageDetails[0].imageDigest' --output text)
echo "Pinned: 123456789012.dkr.ecr.us-west-2.amazonaws.com/rotator@${DIGEST}"
```

---

## 6) Push to OCI OCIR

Set the following environment variables first:
```bash
export OCIR_USERNAME="user@example.com"     # Your console username
export OCIR_AUTH_TOKEN="..."                # User Settings → Auth Tokens
```

Then push:
```bash
make push-ocir   OCIR_REGION=phx   OCIR_NS=mytenancy   OCIR_REPO=rotator   IMAGE_NAME=rotator   IMAGE_TAG=$(git rev-parse --short=12 HEAD)
```

Resulting image URI:
```
phx.ocir.io/mytenancy/rotator:<gitsha>
```

**Tip**: Get the **digest** for Terraform pinning:
```bash
docker inspect --format='{{index .RepoDigests 0}}' phx.ocir.io/mytenancy/rotator:$(git rev-parse --short=12 HEAD)
```

---

## 7) Wire into Terraform (digest pinning recommended)

Update your Terraform variables to reference immutable images. Prefer digests over tags.

### AWS (ECR)
```hcl
# terraform/aws/terraform.auto.tfvars
ecr_image_uri = "123456789012.dkr.ecr.us-west-2.amazonaws.com/rotator@sha256:<digest>"
```

### OCI (OCIR)
```hcl
# terraform/oci/terraform.auto.tfvars
ocir_image_uri = "phx.ocir.io/mytenancy/rotator@sha256:<digest>"
```

**Why**: Digest pinning prevents supply-chain drift and guarantees byte-for-byte identical images at deploy time.

---

## 8) Apply Infrastructure

```bash
# AWS: Secrets Manager, S3 (Glacier IR), KMS, Lambda, EventBridge
make tf-aws-apply AWS_REGION=us-west-2

# OCI: Vault, Object Storage (Archive), Functions, Events, IAM
make tf-oci-apply
```

Ensure the following env/config values are set in your Function/Lambda environments for **Oracle ADB-D** connectivity:
- `OCI_ADB_USER`
- `OCI_ADB_DSN` (TNS alias or EZCONNECT)
- `OCI_ADB_WALLET_MOUNT` **or** `OCI_ADB_WALLET_URL` (short-lived PAR) **or** `OCI_ADB_WALLET_B64` (last resort)

---

## 9) CI Workflow (GitHub Actions)

The provided workflow:
- Builds the image for `linux/amd64`.
- Pushes to **ECR** and **OCIR** tagged with the short Git SHA.
- Prints the URIs you should use in Terraform.

**Secrets to set**:
- `AWS_OIDC_ROLE_ARN`, `AWS_REGION`, `AWS_ACCOUNT_ID`
- `OCIR_REGION`, `OCIR_TENANCY_NAMESPACE`, `OCIR_USERNAME`, `OCIR_AUTH_TOKEN`

**Production Enhancements**:
- Add scan/sign verify steps with hard fail gates.
- Emit digests as workflow outputs; auto-update IaC via PR bots.

---

## 10) Production Hardening Checklist

- Enforce **digest pinning** everywhere (Terraform, Functions).
- Make **scan/sign** gates blocking in CI, not optional.
- Use **customer-managed KMS** for both S3 and Vault; enable key rotation.
- Add **distributed locking** to prevent overlapping rotations.
- Implement **DLQs/alerts** on scheduler failures.
- Remove bootstrap secrets from IaC state; inject secrets at deploy time.
- Configure **least-privilege** bucket and secret resource policies.
- Enable **network egress controls** (NSGs/SGs, NAT) and private endpoints where possible.

---

## Troubleshooting Tips

- **ORA-29024 / SSL**: Wallet not found or TCPS misconfig → verify `config_dir`/`wallet_location` and `tnsnames.ora`.
- **ORA-01017** after rotation: Consumers are caching old creds → retry after re-fetching secrets.
- **RDS auth failures**: Ensure SG rules allow outbound to DB and correct engine (`RDS_ENGINE` variable).

---

## Notes

- This is a PoC. Security gates and operational robustness are intentionally lightweight to focus on clarity.
- The Dockerfile is minimal by design; production should pin base image by **digest** and add provenance verification.
