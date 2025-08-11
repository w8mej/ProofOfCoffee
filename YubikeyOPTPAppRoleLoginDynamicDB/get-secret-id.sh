#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# Purpose: MFA-gated retrieval of a wrapped AppRole secret_id.
# Flow:
#   1) Operator enters a YubiKey OTP (TOTP/HOTP).
#   2) Vault issues a short-lived client token.
#   3) Token is used to request a *wrapped* secret_id (one-time unwrap, TTL 5m).
# Security: secret_id is never printed directly — only a wrapping token is output.
# ---------------------------------------------------------------------------

# Prompt for OTP from YubiKey (physical presence)
read -p "Enter YubiKey OTP: " OTP

# Login to Vault via YubiKey OTP, get a client token (short-lived)
VAULT_TOKEN=$(vault write -field=token auth/yubikey/login otp="$OTP")

# Request a wrapped secret_id (response-wrapping enforces one-time retrieval)
WRAPPED=$(VAULT_TOKEN="$VAULT_TOKEN" vault write -wrap-ttl=5m -field=wrapping_token \
  auth/approle/role/terraform-db/secret-id)

echo "WRAPPED_TOKEN=$WRAPPED"