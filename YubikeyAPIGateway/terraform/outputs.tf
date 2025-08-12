# (Optional) You might want to output Vault paths for debugging/demo purposes
# In a production-safe setup, you would avoid outputting sensitive data here.

output "vault_api_hash_path" {
  description = "Vault path where the API key hash is stored"
  value       = "kv/api/keys/${var.app_name}"
}

output "vault_api_wrapped_path" {
  description = "Vault path where the wrapped API key is stored"
  value       = "kv/api/keys/${var.app_name}/wrapped"
}
