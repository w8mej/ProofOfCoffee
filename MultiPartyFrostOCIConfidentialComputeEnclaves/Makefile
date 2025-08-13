# -----------------------------------------------------------------------------
# File: Makefile
# What it does:
#   Provides convenient targets to build images, generate protobufs, and run the
#   full local stack with docker compose.
#
# Security & Ops notes:
#   - `compose-down` removes volumes to prevent stale state lingering across runs.
#   - Images are built from the local source; pin versions/digests in CI for prod.
#   - Set TEE_POLICY_HASH in your shell to enforce attestation logic across RPCs.
#
# Tunables:
#   - BRANCH filter in CI, DOCKER_* variables for image naming, and TEE_POLICY_HASH.
# -----------------------------------------------------------------------------

SHELL := /bin/bash
.PHONY: proto build images up down logs clean fmt lint

PY := python
PROTO := proto/mpc.proto

# Docker image names (override as needed)
DOCKER_NS ?= local
IMG_COORD ?= $(DOCKER_NS)/mpc-coordinator:dev
IMG_CA    ?= $(DOCKER_NS)/mpc-ca:dev
IMG_TLOG  ?= $(DOCKER_NS)/mpc-tlog:dev
IMG_AUTH  ?= $(DOCKER_NS)/mpc-auth:dev

## Generate Python gRPC stubs
proto:
	$(PY) -m grpc_tools.protoc -I proto $(PROTO) --python_out=gen --grpc_python_out=gen

## Build all service images
images: proto
	docker build -f Dockerfile.coordinator -t $(IMG_COORD) .
	docker build -f Dockerfile.ca          -t $(IMG_CA)    .
	docker build -f Dockerfile.tlog        -t $(IMG_TLOG)  .
	docker build -f Dockerfile.auth        -t $(IMG_AUTH)  .

## Start local stack
up:
	docker compose up -d --build

## Stop and remove containers + volumes (clears ephemeral CA/TLog state)
down:
	docker compose down -v

## Tail logs from all services
logs:
	docker compose logs -f --tail=200

## Clean generated artifacts
clean:
	rm -rf gen/*

## Optional: simple formatting/lint hooks (add ruff/black if desired)
fmt:
	@echo "Add black/ruff if you want auto-formatting"

lint:
	@echo "Add ruff/pylint if you want linting"
