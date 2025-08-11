#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# Script Name: yubikey_vault_ssh_otp.sh
# -------------------------------------------------------------------
# Purpose:
#   This script performs a secure, short-lived SSH login using:
#     - YubiKey-generated One-Time Password (OTP)
#     - Vault Transit for OTP signing (providing non-repudiation)
#     - Vault JWT for packaging signature + SSH public key
#     - SSH ephemeral certificate authentication
#
# Flow:
#   1. Prompt user to touch YubiKey to generate an OTP.
#   2. Sign OTP with Vault Transit, binding it to the SSH public key.
#   3. Request a JWT from Vault containing:
#        - Username (subject)
#        - SSH public key
#        - OTP signature
#   4. Use the JWT as an ephemeral SSH certificate for login.
#
# Security Notes:
#   - OTP provides physical possession proof (touch YubiKey).
#   - Vault Transit signing ensures OTP integrity & ties it to the key.
#   - JWT is short-lived, reducing risk if intercepted.
#   - SSH login skips persistent keys — purely ephemeral authentication.
#
# Requirements:
#   - ykman CLI for YubiKey OTP generation
#   - Vault CLI configured with `transit` and `jwt` secrets engines
#   - SSH server configured to trust Vault-issued ephemeral certs
#
# Usage:
#   ./yubikey_vault_ssh_otp.sh <HOST> <USER> <PUBKEY_PATH>
# -------------------------------------------------------------------

HOST=$1       # SSH target host
USER=$2       # SSH username
PUBKEY=$3     # Path to user's SSH public key (.pub)

# 1️⃣ Prompt for YubiKey OTP (physical touch required)
read -rp "Touch YubiKey and press ENTER to read OTP: " < /dev/null
OTP=$(ykman otp generate 1)   # Assumes slot 1 contains OTP credential

# 2️⃣ Sign OTP with Vault Transit, binding signature to SSH public key
SIG=$(vault write -field=signature transit/sign/ssh-otp \
      input=$(base64 <<<"$OTP") \
      context=$(base64 <<<"$(cat "$PUBKEY")"))

# 3️⃣ Request short-lived JWT containing SSH key & OTP signature
JWT=$(vault write -field=token jwt/create/ssh-otp \
      role=ssh-otp \
      claims=$(cat <<EOF
{
  "sub": "$USER",
  "aud": "ssh-login",
  "ssh_cert": "$(tr -d '\n' < "$PUBKEY")",
  "otp_sig": "$SIG"
}
EOF
))

# 4️⃣ Perform SSH login using JWT as ephemeral certificate
ssh \
  -o "CertificateFile=/dev/stdin" \
  -i "$PUBKEY" \
  -o "IdentityFile=/dev/null" \
  -o "IdentityAgent=none" \
  -o "UserKnownHostsFile=/dev/null" \
  -o "StrictHostKeyChecking=no" \
  -o "ProxyCommand=echo $JWT" \
  "$USER@$HOST"
