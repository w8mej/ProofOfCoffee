# ------------------------------------------------------------------------------
# Makefile — Zero-Trust Minting PoC
#
# Purpose:
#   Provides local development, testing, build, and deployment automation for:
#     • Python virtual environment setup
#     • MPC/FROST key share initialization
#     • Running the FastAPI mint API locally
#     • Kubernetes deployment of FROST signers/coordinator
#     • Docker image build/push for FROST services
#     • OPA (Open Policy Agent) policy formatting, testing, and bundle creation
#
# Environment Variables:
#   OPA           — Path to the opa binary (default: opa)
#   BUNDLE_OUT    — Output directory for policy bundle (default: build/policy)
#   BUNDLE_NAME   — Bundle tarball name (default: secure_bundle.tar.gz)
# ------------------------------------------------------------------------------

OPA ?= opa
BUNDLE_OUT ?= build/policy
BUNDLE_NAME ?= secure_bundle.tar.gz

.PHONY: init venv run api test shares clean \
        k8s-frost-apply k8s-frost-delete build-frost push-frost \
        k8s-certs-apply k8s-netpol-apply k8s-frost-netpol-apply k8s-frost-netpol-delete \
        policy-fmt policy-test policy-bundle policy-publish clean-policy

# ------------------------------------------------------------------------------
# Python virtual environment & dependencies
# ------------------------------------------------------------------------------
venv:
	python3 -m venv .venv && \
	. .venv/bin/activate && \
	pip install -U pip && \
	pip install -r requirements.txt

# ------------------------------------------------------------------------------
# Initialize MPC/FROST key shares locally
# Example: 3 total shares, threshold 2, output to .mpc_shares directory
# ------------------------------------------------------------------------------
init: venv
	. .venv/bin/activate && \
	python -m src.mpc.shares --init --n 3 --t 2 --out .mpc_shares

# ------------------------------------------------------------------------------
# Run FastAPI API locally with auto-reload (dev mode)
# ------------------------------------------------------------------------------
api:
	. .venv/bin/activate && \
	uvicorn src.server.api:app --reload --port 8080

# ------------------------------------------------------------------------------
# Run CLI tool for minting demonstration
# ------------------------------------------------------------------------------
run:
	. .venv/bin/activate && \
	python -m src.cli.mint --help

# ------------------------------------------------------------------------------
# Run unit tests via pytest
# ------------------------------------------------------------------------------
test:
	. .venv/bin/activate && \
	python -m pytest -q

# ------------------------------------------------------------------------------
# Clean local build/test artifacts
# ------------------------------------------------------------------------------
clean:
	rm -rf .venv .mpc_shares __pycache__ .pytest_cache dist build

# ------------------------------------------------------------------------------
# Kubernetes: Deploy FROST components
# Apply namespace, secrets (replace example in prod), DaemonSet signers, service,
# and coordinator deployment.
# ------------------------------------------------------------------------------
k8s-frost-apply:
	kubectl apply -f k8s/frost/namespace.yaml
	kubectl apply -f k8s/frost/secrets.example.yaml # replace before prod
	kubectl apply -f k8s/frost/daemonset.yaml
	kubectl apply -f k8s/frost/service.yaml
	kubectl apply -f k8s/frost/coordinator.yaml

# Remove FROST resources from cluster
k8s-frost-delete:
	kubectl delete -f k8s/frost/coordinator.yaml || true
	kubectl delete -f k8s/frost/service.yaml || true
	kubectl delete -f k8s/frost/daemonset.yaml || true
	kubectl delete -f k8s/frost/secrets.example.yaml || true
	kubectl delete -f k8s/frost/namespace.yaml || true

# ------------------------------------------------------------------------------
# Docker: Build and push FROST signer/coordinator images
# ------------------------------------------------------------------------------
build-frost:
	docker build -t ghcr.io/your-org/frost:latest frost

push-frost:
	echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
	docker push ghcr.io/your-org/frost:latest

# ------------------------------------------------------------------------------
# Kubernetes: Apply TLS certs for FROST via cert-manager
# ------------------------------------------------------------------------------
k8s-certs-apply:
	kubectl apply -f k8s/cert-manager/cluster-issuers.yaml
	kubectl apply -f k8s/frost/namespace.yaml
	kubectl apply -f k8s/cert-manager/frost-certs.yaml

# ------------------------------------------------------------------------------
# Kubernetes: Apply network policies for FROST
# ------------------------------------------------------------------------------
k8s-netpol-apply:
	kubectl apply -f k8s/frost/networkpolicies.yaml

k8s-frost-netpol-apply:
	kubectl apply -f k8s/frost/networkpolicies.yaml

k8s-frost-netpol-delete:
	kubectl delete -f k8s/frost/networkpolicies.yaml || true

# ------------------------------------------------------------------------------
# OPA Policy management
# ------------------------------------------------------------------------------
# Format all .rego files in policy/ in-place
policy-fmt:
	$(OPA) fmt -w policy

# Run OPA unit tests on policy/
policy-test:
	$(OPA) test -v policy

# Create tar.gz bundle of policies (plus optional policy/data)
policy-bundle: clean-policy policy-fmt policy-test
	mkdir -p $(BUNDLE_OUT)/policy
	cp -r policy/*.rego $(BUNDLE_OUT)/policy/
	if [ -d policy/data ]; then \
		mkdir -p $(BUNDLE_OUT)/policy/data && \
		cp -r policy/data/* $(BUNDLE_OUT)/policy/data/; \
	fi
	cd $(BUNDLE_OUT) && tar czf $(BUNDLE_NAME) policy

# Simulate publishing the policy bundle (in CI this would upload artifact/release)
policy-publish: policy-bundle
	@echo "Uploading bundle artifact (local)…"
	@echo "Bundle at $(BUNDLE_OUT)/$(BUNDLE_NAME)"
	@echo "In CI this is uploaded as a workflow artifact or release."

# Remove generated policy bundles
clean-policy:
	rm -rf $(BUNDLE_OUT)