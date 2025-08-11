# Variable: state_key
# ---------------------------------------------------------------------------
# Holds a Base64-encoded AES-256 key, typically derived from Vault's Transit
# secrets engine. This key will be used to encrypt/decrypt sensitive data
# in our Proof of Concept.
# NOTE: Passing encryption keys as variables is NOT secure for production use.
#       Keys should be sourced from a secure secret manager or HSM.
variable "state_key" {
  description = "Base64-encoded AES-256 key (derived from Vault Transit)"
  type        = string
}

# Local: aes_key
# ---------------------------------------------------------------------------
# Decodes the Base64 representation of the key into its raw binary form,
# making it usable for cryptographic operations in this PoC.
locals {
  aes_key = base64decode(var.state_key)
}
