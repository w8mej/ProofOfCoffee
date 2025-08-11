#!/usr/bin/env bash
# -------------------------------------------------------------------
# Script Name: vault_unseal_with_yubikey_otp.sh
# -------------------------------------------------------------------
# Purpose:
#   Automates the process of unsealing a Vault cluster by retrieving
#   Shamir unseal shares that are encrypted and bound to a one-time 
#   password (OTP) from a YubiKey.
#
# Overview:
#   1. Prompt the operator for a fresh YubiKey OTP.
#   2. Derive a per-execution HMAC key from that OTP.
#   3. Retrieve encrypted unseal shares from Vault’s KV store.
#   4. Decrypt each share using the Vault Transit engine, with the
#      OTP-derived key as the encryption context.
#   5. Feed the decrypted shares to `vault operator unseal`.
#
# Security Highlights:
#   - **Per-session key derivation** from YubiKey OTP ensures that 
#     unseal shares are useless without both:
#       (a) Access to the Vault KV ciphertexts, and
#       (b) A physical YubiKey to produce the OTP.
#   - **Encryption context binding** via Vault Transit engine prevents
#     ciphertext reuse outside of the intended OTP session.
#   - **No persistent storage** of decrypted shares; all in-memory.
#   - Any *m*-of-*n* unseal threshold can be satisfied by adjusting 
#     the number of shares retrieved in the loop.
#
# Usage:
#   VAULT_ADDR=http://vault.haxx.ninja:8200 \
#   VAULT_TOKEN=sometoken \
#   ./vault_unseal_with_yubikey_otp.sh
#
#   (Prompts for YubiKey OTP interactively)
#
# Requirements:
#   - `vault` CLI configured for the target instance.
#   - OpenSSL, xxd, and base64 utilities available.
#   - YubiKey programmed for OTP mode.
#   - Pre-configured Vault Transit key named in $TRANSIT_KEY.
#   - Encrypted shares stored in `secret/unseal-share/<id>` KV paths.
# -------------------------------------------------------------------

set -euo pipefail

VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
TRANSIT_KEY=unseal-share

# 1️⃣ Prompt for a fresh YubiKey OTP
read -rp "Enter YubiKey OTP: " OTP

# 2️⃣ Derive a per-execution HMAC key from OTP
KEY=$(echo -n "$OTP" \
      | openssl dgst -sha256 -hmac "vault-unseal-share" -binary \
      | xxd -p -c 256)

# Function: Retrieve and decrypt a single unseal share
get_share() {
  local id=$1

  # a) Retrieve encrypted share from KV
  CIPHER=$(vault kv get -field=ciphertext secret/unseal-share/$id)

  # b) Optionally create a temporary Transit key (demo placeholder)
  vault write -f transit/keys/tmp-key type=aes256-gcm96

  # c) (Rewrap trick could be applied here; in this flow we directly decrypt)
  SHARE=$(vault write -field=plaintext transit/decrypt/$TRANSIT_KEY \
          ciphertext="$CIPHER" \
          context=$(echo -n "$KEY" | base64) \
        | base64 -d)

  echo "$SHARE"
}

# 3️⃣ Retrieve enough shares to meet Vault's unseal threshold
SHARES=()
for i in 1 2 3; do   # Adjust indices based on your m-of-n config
  SHARES+=("$(get_share $i)")
done

# 4️⃣ Submit shares to unseal Vault
for s in "${SHARES[@]}"; do
  vault operator unseal "$s"
done

echo "✅ Vault is now unsealed!"
