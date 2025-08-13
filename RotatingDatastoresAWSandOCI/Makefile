################################################################################
# Multi-Cloud Credential Rotator — Makefile (PoC)
#
# Purpose:
#   Build a single container image for a worker that rotates a shared DB
#   credential across AWS RDS (PostgreSQL/MySQL) and OCI Autonomous DB
#   (Dedicated Exadata), then push to both ECR and OCIR and deploy infra
#   for a scheduled rotation every 20 minutes.
#
# Status:
#   PROOF OF CONCEPT — NOT PRODUCTION-READY.
#
# Security posture (PoC-conscious):
#   - Zero plaintext secrets in logs (enforced in app code; this file adds
#     basic supply-chain hooks).
#   - Pushes to private registries only (ECR/OCIR).
#   - Least-privilege IAM/Policies are defined in Terraform modules,
#     parameterized for exact ARNs/OCIDs (no wildcards).
#
# NOT production yet — Missing/Optional hardening to add before GA:
#   [ ] Provenance/SBOM publication & verification (syft/cosign attest).
#   [ ] Mandatory image scanning gate (trivy/grype) with fail-on-high.
#   [ ] Registry signing & verification policies (cosign + registry rules).
#   [ ] Conftest/OPA policy gate for Terraform plans.
#   [ ] Enforced build reproducibility (SLSA-3+ compliant pipeline).
#   [ ] Secrets & wallet handling through short-lived references only
#       (PAR TTL rotation by pipeline; already supported in app code).
################################################################################

# -------- Variables (override via env or CLI: `make VAR=value target`) --------

# Image + registries
IMAGE_NAME        ?= rotator
IMAGE_TAG        ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo dev)
PLATFORM          ?= linux/amd64

# Build context (matches your repo layout)
CONTEXT_DIR       ?= infra/shared/image

# AWS ECR
AWS_REGION        ?= us-west-2
AWS_ACCOUNT_ID    ?= 123456789012
ECR_REPO          ?= $(IMAGE_NAME)
ECR_REGISTRY      := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ECR_IMAGE_URI     := $(ECR_REGISTRY)/$(ECR_REPO):$(IMAGE_TAG)

# OCI OCIR
OCIR_REGION       ?= phx          # e.g., phx, iad, fra
OCIR_NS           ?= mytenancy    # tenancy namespace
OCIR_REPO         ?= $(IMAGE_NAME)
OCIR_REGISTRY     := $(OCIR_REGION).ocir.io/$(OCIR_NS)
OCIR_IMAGE_URI    := $(OCIR_REGISTRY)/$(OCIR_REPO):$(IMAGE_TAG)
# Requires:
#   export OCIR_USERNAME="user@example.com"  (or federated form)
#   export OCIR_AUTH_TOKEN="…"               (OCI User -> Auth Tokens)

# Terraform roots
INFRA_AWS         ?= infra/aws
INFRA_OCI         ?= infra/oci

# Optional security tooling (PoC hooks; safe to ignore if not installed)
TRIVY_BIN         ?= trivy
SYFT_BIN          ?= syft
COSIGN_BIN        ?= cosign

# ------------------------------ Utility helpers ------------------------------

.PHONY: help
help:
	@echo ""
	@echo "Multi-Cloud Credential Rotator — Makefile (PoC)"; \
	echo ""; \
	echo "Core targets:"; \
	echo "  build           Build the worker image ($(PLATFORM))"; \
	echo "  push-ecr        Push image to AWS ECR ($(ECR_IMAGE_URI))"; \
	echo "  push-ocir       Push image to OCI OCIR ($(OCIR_IMAGE_URI))"; \
	echo "  push-all        Push to both registries"; \
	echo "  tf-aws-apply    Terraform apply the AWS stack ($(INFRA_AWS))"; \
	echo "  tf-oci-apply    Terraform apply the OCI stack ($(INFRA_OCI))"; \
	echo "  all             Build, push-all, and apply both stacks"; \
	echo ""; \
	echo "Security (optional PoC hooks):"; \
	echo "  sbom            Generate SBOM (spdx-json) with syft"; \
	echo "  scan            Scan image with trivy (does not fail build)"; \
	echo "  sign            Sign image with cosign (keyless if configured)"; \
	echo ""; \
	echo "Variables override examples:"; \
	echo "  make build IMAGE_TAG=$$(git rev-parse --short HEAD)"; \
	echo "  make push-ecr AWS_ACCOUNT_ID=000... AWS_REGION=us-east-1"; \
	echo ""

# Fail early if a required CLI is missing.
# Usage: $(call require,cmd-name,install-url)
require = \
	if ! command -v $(1) >/dev/null 2>&1; then \
	  echo "ERROR: Missing dependency: $(1). Please install → $(2)"; \
	  exit 127; \
	fi

# --------------------------------- Build -------------------------------------

.PHONY: build
## Build the Linux/amd64 image. Uses buildx for consistent CI parity.
build:
	$(call require,docker,https://docs.docker.com/get-docker/)
	docker buildx build --platform $(PLATFORM) -t $(IMAGE_NAME):$(IMAGE_TAG) $(CONTEXT_DIR)

# ------------------------------- Push: AWS ECR -------------------------------

.PHONY: login-ecr
## Log in to ECR. Creates the repository if it doesn't exist (idempotent).
login-ecr:
	$(call require,aws,https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
	aws ecr get-login-password --region $(AWS_REGION) | \
	  docker login --username AWS --password-stdin $(ECR_REGISTRY)
	@aws ecr describe-repositories --repository-names $(ECR_REPO) --region $(AWS_REGION) >/dev/null 2>&1 || \
	  aws ecr create-repository --repository-name $(ECR_REPO) --region $(AWS_REGION) >/dev/null

.PHONY: push-ecr
## Tag and push the image to ECR.
push-ecr: build login-ecr
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(ECR_IMAGE_URI)
	docker push $(ECR_IMAGE_URI)

# ------------------------------- Push: OCIR ----------------------------------

.PHONY: login-ocir
## Log in to OCIR using OCI Auth Token (NEVER store the token in the repo/CI logs).
login-ocir:
	$(call require,docker,https://docs.docker.com/get-docker/)
	@if [ -z "$$OCIR_USERNAME" ] || [ -z "$$OCIR_AUTH_TOKEN" ]; then \
	  echo "ERROR: Set OCIR_USERNAME and OCIR_AUTH_TOKEN env vars before login-ocir"; \
	  exit 2; \
	fi
	echo "$$OCIR_AUTH_TOKEN" | docker login $(OCIR_REGION).ocir.io -u "$(OCIR_NS)/$$OCIR_USERNAME" --password-stdin

.PHONY: push-ocir
## Tag and push the image to OCIR.
push-ocir: build login-ocir
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(OCIR_IMAGE_URI)
	docker push $(OCIR_IMAGE_URI)

.PHONY: push-all
## Push to both registries (order is arbitrary in PoC).
push-all: push-ecr push-ocir

# ------------------------------- Terraform -----------------------------------

.PHONY: tf-aws-apply
## Apply AWS infrastructure (creates SM secrets, S3 audit bucket, IAM, Lambda, schedule).
tf-aws-apply:
	$(call require,terraform,https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
	cd $(INFRA_AWS) && terraform init && terraform apply -auto-approve

.PHONY: tf-oci-apply
## Apply OCI infrastructure (creates Vault secrets, Object Storage bucket, Functions, schedule).
tf-oci-apply:
	$(call require,terraform,https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
	cd $(INFRA_OCI) && terraform init && terraform apply -auto-approve

# ----------------------------- Security (PoC) --------------------------------
# These targets demonstrate intent; they do NOT block the pipeline in this PoC.
# For production, convert these into mandatory, failing gates.

.PHONY: sbom
## Generate an SBOM (spdx-json) for the image (requires syft).
sbom:
	@command -v $(SYFT_BIN) >/dev/null 2>&1 || { echo "skipping: syft not found"; exit 0; }
	$(SYFT_BIN) $(IMAGE_NAME):$(IMAGE_TAG) -o spdx-json > sbom-$(IMAGE_NAME)-$(IMAGE_TAG).spdx.json
	@echo "SBOM written to sbom-$(IMAGE_NAME)-$(IMAGE_TAG).spdx.json"

.PHONY: scan
## Scan the built image for CVEs (requires trivy). Non-fatal in PoC.
scan:
	@command -v $(TRIVY_BIN) >/dev/null 2>&1 || { echo "skipping: trivy not found"; exit 0; }
	$(TRIVY_BIN) image --scanners vuln,secret --severity HIGH,CRITICAL $(IMAGE_NAME):$(IMAGE_TAG) || true

.PHONY: sign
## Sign the image with cosign (keyless if your environment supports it). Non-fatal in PoC.
sign:
	@command -v $(COSIGN_BIN) >/dev/null 2>&1 || { echo "skipping: cosign not found"; exit 0; }
	$(COSIGN_BIN) sign --yes $(ECR_IMAGE_URI) || true
	$(COSIGN_BIN) sign --yes $(OCIR_IMAGE_URI) || true

# ------------------------------ Convenience ----------------------------------

.PHONY: all
## Build, push to both registries, and apply both stacks (PoC fast path).
all: build push-all tf-aws-apply tf-oci-apply

.PHONY: clean
## Remove the local image tag (does not delete remote images).
clean:
	-docker rmi $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || true

# End of Makefile

