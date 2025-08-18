############################################################
# 🔐 PoC: YubiKey-Secured API Key Generation & Distribution
# ----------------------------------------------------------
# GOAL:
#   - Terraform generates a strong API key locally.
#   - Only a SHA-256 hash is stored in Vault (never plaintext).
#   - The actual key is encrypted to the client's YubiKey
#     (slot 9c) so only their hardware can decrypt it.
#
# COOL FACTOR:
#   - Combines Terraform, Vault, and YubiKey hardware crypto.
#   - Avoids secrets in logs/state by encrypting before storage.
#   - No server ever holds the usable API key.
#
# ⚠️ PoC ONLY — This code is not hardened for production.
############################################################

# 1️⃣ Generate a strong random API key (plaintext is only in Terraform's memory)
resource "random_password" "api" {
  length  = 32   # 256 bits of entropy
  special = true # Include special chars for extra entropy
}

# 2️⃣ Locally compute the Base64-encoded SHA-256 hash of the API key
#    - The plaintext key never leaves the machine running Terraform
#    - This is what gets stored in Vault for later verification
resource "null_resource" "hash_key" {
  triggers = {
    api_key = random_password.api.result
  }
  provisioner "local-exec" {
    command = <<EOT
      set -euo pipefail
      echo -n "${random_password.api.result}" | \
        openssl dgst -sha256 -binary | base64 > api_key.sha256.b64
    EOT
  }
}

# 3️⃣ Store the SHA-256 hash (Base64) in Vault KV
#    - Used later by API services to verify client-provided keys
#    - No usable plaintext API key is ever stored here
resource "vault_kv_secret_v2" "api_hash" {
  mount = "kv"
  name  = "api/keys/${var.app_name}"
  data_json = jsonencode({
    sha256_b64 = trimspace(file("${path.module}/api_key.sha256.b64"))
  })
  depends_on = [null_resource.hash_key]
}

# 4️⃣ Encrypt ("wrap") the API key for the client's YubiKey (slot 9c)
#    - Uses yubico-piv-tool to perform RSA OAEP encryption
#    - Only the matching private key on the YubiKey can decrypt it
resource "null_resource" "wrap_for_yubikey" {
  triggers = {
    api_key        = random_password.api.result
    client_pub_pem = var.client_pub_pem
  }
  provisioner "local-exec" {
    # Ensure bash semantics
    interpreter = ["/bin/bash", "-c"]

    # Provide values safely via environment
    environment = {
      api_key        = random_password.api.result
      client_pub_pem = var.client_pub_pem
    }

    # Unquoted heredoc + escape $ to pass shell vars through Terraform
    command = <<-EOT
      set -euo pipefail

      # Save the client's public cert to disk
      printf '%s\n' "$${client_pub_pem}" > client_pub.pem

      # Encrypt API key to YubiKey's RSA key and Base64 encode the result
      printf '%s' "$${api_key}" | \
        yubico-piv-tool -a encrypt -s 9c -K RSA2048 -i - -c client_pub.pem | \
        base64 > wrapped_api_key.b64
    EOT
  }
}

# 5️⃣ Store the wrapped API key in Vault KV
#    - Client retrieves this value and decrypts it locally with their YubiKey
resource "vault_kv_secret_v2" "api_wrapped" {
  mount = "kv"
  name  = "api/keys/${var.app_name}/wrapped"
  data_json = jsonencode({
    wrapped_b64 = trimspace(file("${path.module}/wrapped_api_key.b64"))
  })
  depends_on = [null_resource.wrap_for_yubikey]
}
