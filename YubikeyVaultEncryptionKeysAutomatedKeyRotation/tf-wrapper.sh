#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# Proof of Concept: Retrieve and decrypt a Terraform state encryption key 
# stored in Vault, using a YubiKey for hardware-backed decryption.
#
# This demo script:
#   1. Fetches a wrapped encryption seed from Vault KV.
#   2. Decrypts it with a YubiKey private key (slot 9c).
#   3. Derives an AES-256 key via Vault's Transit engine.
#   4. Exports the key for Terraform to use when encrypting state.
# WARNING: Not suitable for production — lacks key rotation policies,
#          secure ephemeral storage, and proper secrets hygiene.
# ---------------------------------------------------------------------------

# 1️⃣ Load the wrapped seed from Vault's KV store (field: data.key)
WRAPPED=$(vault kv get -field=data kv/terraform/state | jq -r .key)

# 2️⃣ Base64-decode and save to a temporary file for decryption
echo "$WRAPPED" | base64 -d > wrapped.bin

# 3️⃣ Use YubiKey (slot 9c) to decrypt the wrapped seed (RSA OAEP)
SEED=$(yubico-piv-tool -a decrypt -s 9c -i wrapped.bin | base64)

# 4️⃣ Encrypt the seed via Vault Transit to derive a ciphertext-form AES-256 key
ENCRYPTED=$(vault write -field=ciphertext transit/encrypt/terraform-state \
    plaintext=$(echo -n "$SEED" | base64))

# 5️⃣ Export just the raw ciphertext portion for Terraform to consume
export TF_VAR_state_key=$(echo "$ENCRYPTED" | cut -d'_' -f2)

# 6️⃣ Initialize and apply Terraform with the hardware-derived key
terraform init
terraform apply -auto-approve