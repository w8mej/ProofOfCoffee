#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# Proof of Concept: Rotate Terraform state encryption key using a YubiKey.
# This demo script:
#   1. Generates a new AES-256 seed.
#   2. Encrypts it with a YubiKey hardware key.
#   3. Stores the encrypted value in Vault KV for later retrieval.
# WARNING: This script is for demonstration only — it lacks production-grade
#          key lifecycle management, error handling, and auditing.
# ---------------------------------------------------------------------------

# 1️⃣ Generate a fresh 256-bit encryption seed (Base64-encoded for transport).
NEW_SEED=$(openssl rand -base64 32)

# 2️⃣ Encrypt ("wrap") the seed using the YubiKey's private key in slot 9c,
#     then Base64-encode the wrapped key for safe storage.
WRAPPED_NEW=$(echo -n "$NEW_SEED" | \
  yubico-piv-tool -a encrypt -s 9c -i - | base64)

# 3️⃣ Store the wrapped seed in Vault's KV store under 'kv/terraform/state'.
vault kv put kv/terraform/state key=$WRAPPED_NEW

# Status output for visibility.
echo "Rotation complete."