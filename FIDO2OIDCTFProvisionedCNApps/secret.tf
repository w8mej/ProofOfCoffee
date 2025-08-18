############################################
# Vault: API Key for Lambda
############################################
resource "vault_kv_secret_v2" "api_key" {
  mount = "kv"
  name  = "lambda/api-key"
  data_json = jsonencode({
    key = "super-secret-api-key-123"
  })
}



