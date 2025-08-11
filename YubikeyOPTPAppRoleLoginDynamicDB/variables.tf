############################################
# Input variable: wrapped response-wrapping token
# - Produced by the OTP-gated script (Example 1).
# - Unwrapped by Terraform (Example 4) to obtain secret_id.
# Security: Keep distribution of this value tight; short TTL helps.
############################################
variable "wrapped_token" {
  description = "Wrapped token containing the secret_id (output from get-secret-id.sh)"
  type        = string
}
