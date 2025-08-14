# -----------------------------------------------------------------------------
# FROST services Dockerfile (multi-stage)
#
# Security & Ops
# - Build in a separate stage; ship only the compiled binaries in a slim runtime.
# - Compile with Cargo.lock enforced (`--locked`) for supply-chain stability.
# - Run as a non-root user; keep the runtime image minimal (no compilers, no git).
# - Pin APT packages; avoid `--no-install-recommends` bloat.
# - Healthcheck probes local /healthz endpoints for signer/coordinator.
#
# Tunables / Config
# - You can set `CARGO_PROFILE_RELEASE_LTO` or RUSTFLAGS via build args if desired.
# - Enable BuildKit cache mounts to speed up dependency builds (see notes below).
#
# Improvements / Production
# - Consider distroless if you can drop curl (move health to k8s probes).
# - Sign/push image with provenance (cosign/SLSA); pin by digest in k8s manifests.
# - Add SBOM (e.g., `cargo auditable`) and run `cargo-audit` in CI.
# -----------------------------------------------------------------------------

# ---------------------------
# Builder stage: compile Rust
# ---------------------------
FROM rust:1.79 AS builder

# (Optional) Helpful labels for provenance in CI
LABEL org.opencontainers.image.source="https://github.com/your-org/zero-trust-api-key-minting"
LABEL org.opencontainers.image.description="FROST threshold Ed25519 services (keygen, signer, coordinator)"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /code

# If using BuildKit, uncomment to cache dependencies across builds:
# RUN --mount=type=cache,target=/usr/local/cargo/registry \
#     --mount=type=cache,target=/code/target \
#     cargo fetch

# Copy workspace and build release binaries with lockfile enforced
COPY . .
# Enforce lockfile to avoid supply-chain drift; build only the needed packages.
RUN cargo build --release --locked \
    -p frost-keygen \
    -p frost-signer \
    -p frost-coordinator

# Note: You could strip binaries here if desired, e.g., with `llvm-strip`,
# but the stock rust image may not include it. Alternatively, compile with:
#   RUSTFLAGS="-C strip=symbols" cargo build --release
# or strip in the final stage by installing binutils (not recommended for minimal image).

# ---------------------------
# Runtime stage: minimal OS
# ---------------------------
FROM debian:bookworm-slim

# Security: minimal packages, pinned versions, no recommends; non-root user.
# We include curl only for the HEALTHCHECK. If k8s probes are used instead,
# you can remove curl and the HEALTHCHECK to shrink the image further.
RUN useradd -m app \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates=20230311 \
      curl=7.88.1-10+deb12u7 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the three service binaries from the builder
# Use --chown to avoid root-owned files in the final image
COPY --from=builder --chown=app:app /code/target/release/frost-keygen /usr/local/bin/frost-keygen
COPY --from=builder --chown=app:app /code/target/release/frost-signer /usr/local/bin/frost-signer
COPY --from=builder --chown=app:app /code/target/release/frost-coordinator /usr/local/bin/frost-coordinator

# Drop privileges
USER app

# Default CMD is a harmless hint; k8s manifests should set explicit commands.
CMD ["bash","-lc","echo 'Provide a specific binary as CMD (frost-keygen|frost-signer|frost-coordinator)'"]

# Health: try signer (7000) then coordinator (7100). If neither responds, fail.
# If you deploy only one service per container, override this in k8s or remove it.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:7000/healthz || curl -fsS http://127.0.0.1:7100/healthz || exit 1