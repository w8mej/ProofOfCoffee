############################################
# Vault Policy: Read-Only Access for Lambda
# ------------------------------------------
# Purpose:
#   Grants the Lambda function read access to
#   all secrets stored under the "lambda/"
#   path in the KV v2 secrets engine.
#
# Security Considerations:
#   - Capability is restricted to ["read"] only.
#   - No write/update/delete to prevent
#     accidental or malicious modification.
#   - Uses wildcard (*) to allow flexibility
#     for multiple secrets, but path can be
#     narrowed for tighter least-privilege.
############################################

path "kv/data/lambda/*" {
  capabilities = ["read"]
}
