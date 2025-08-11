#!/usr/bin/env bash
# -------------------------------------------------------------------
# Script Name: ssh_jwt_verifier.sh
# -------------------------------------------------------------------
# Purpose:
#   This script is invoked by SSH (via AuthorizedKeysCommand or 
#   AuthorizedPrincipalsCommand) to verify a client’s ephemeral
#   JWT-issued SSH certificate.
#
# Workflow:
#   1. Accepts:
#        $1 → username requesting SSH access
#        $2 → SSH public key (base64-encoded) from the client
#   2. Reads JWT from the SSH_JWT environment variable, which the
#      client provides via ProxyCommand during connection.
#   3. Calls Vault’s JWT verify endpoint to validate:
#        - Token signature
#        - Token audience = "ssh-login"
#   4. If valid, outputs the corresponding SSH principal 
#      (employee-<username>) for session authorization.
#   5. If invalid, exits non-zero to deny login.
#
# Security Notes:
#   - No persistent SSH keys; trust is established per-login.
#   - Vault JWT verification enforces centralized trust policy.
#   - JWT’s short TTL minimizes credential replay risk.
#
# Usage (Server-Side):
#   1. Configure SSHD to call this script as AuthorizedPrincipalsCommand:
#        AuthorizedPrincipalsCommand /path/to/ssh_jwt_verifier.sh %u %k
#        AuthorizedPrincipalsCommandUser nobody
#   2. Ensure `vault` CLI is available and configured to talk to Vault.
#   3. Client must set SSH_JWT env var in ProxyCommand during login.
# -------------------------------------------------------------------

USER=$1
PUBKEY_B64=$(echo -n "$2" | base64 -d)

# Read the JWT from the SSH client environment
JWT=$(echo "$SSH_JWT")

# Verify the JWT against Vault (audience must match "ssh-login")
if vault write -field=valid jwt/verify/ssh-otp token="$JWT" audience=ssh-login; then
    # Output the SSH principal associated with the username
    echo "employee-$USER"
else
    # Invalid token — deny access
    exit 1
fi
