#!/usr/bin/env bash
# ============================================================
# Proof of Concept: Retrieve and Decrypt an API Key via YubiKey
# ------------------------------------------------------------
# - Demonstrates secure retrieval of a wrapped API key from Vault.
# - The API key itself is never stored in plaintext in Vault logs
#   or Terraform state; only a wrapped/encrypted form is stored.
# - Decryption happens locally on a hardware-backed YubiKey (slot 9c).
#
# ⚠️ PoC ONLY — Not production-hardened. Error handling and security
# hardening would be required for real-world deployment.
#
# Usage:
#   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
#       ./scripts/unwrap_api_key.sh <app_name>
#
# Example:
#   ./unwrap_api_key.sh myapp
# ============================================================

set -euo pipefail  # Fail fast on errors, unset vars, and pipeline failures

# 🎯 The target app name for which to retrieve the API key
APP="${1:?app name required}"

# 1️⃣ Pull the Base64-encoded, wrapped API key from Vault KV
#    - Path pattern: kv/api/keys/<app_name>/wrapped
#    - Vault returns the value in the 'wrapped_b64' field
WRAPPED_B64=$(vault kv get -field=wrapped_b64 "kv/api/keys/${APP}/wrapped")

# 2️⃣ Decode from Base64 and save as a temporary binary file
echo "$WRAPPED_B64" | base64 -d > wrapped.bin

# 3️⃣ Decrypt the wrapped key using the YubiKey hardware slot 9c
#    - This uses RSA OAEP decryption on the secure element
API_KEY=$(yubico-piv-tool -a decrypt -s 9c -i wrapped.bin)

# 4️⃣ Clean up sensitive temporary files
rm -f wrapped.bin

# 5️⃣ Output the plaintext API key to stdout
#    - In production, you’d likely pipe this directly to a consumer
#      rather than printing it
echo "$API_KEY"