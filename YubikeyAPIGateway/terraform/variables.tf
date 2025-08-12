# Vault server address (e.g., dev server for PoC)
variable "vault_addr" {
  description = "Vault URL (e.g., http://127.0.0.1:8200)"
  type        = string
}

# Vault token — for PoC we use a static root token
# In production: use AppRole or OIDC for automation
variable "vault_token" {
  description = "Vault token (short-lived preferred)"
  type        = string
  sensitive   = true
}

# Logical name for the app the API key belongs to
variable "app_name" {
  description = "Logical application name for the API key"
  type        = string
  default     = "myapp"
}

# PEM-formatted public certificate from the client's YubiKey
# Used to encrypt the API key so only their hardware can decrypt
variable "client_pub_pem" {
  description = "Client's YubiKey PIV certificate (PEM) used to wrap the API key"
  type        = string
}
