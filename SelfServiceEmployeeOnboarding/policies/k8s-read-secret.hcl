# -------------------------------------------------------------------
# Vault Policy: GitHub Token Read Access
# -------------------------------------------------------------------
# Purpose:
#   Grants read-only access to a GitHub personal access token stored
#   in Vault at the KV v2 path `secret/data/github-token`.
#
# Usage Scenario:
#   - Used by CI/CD pipelines or automation scripts that require
#     a GitHub token to authenticate API calls or clone private repos.
#   - Should be bound to a Vault Role with minimal scope so that
#     only the required service or user has this capability.
#
# Security Notes:
#   - `read` capability is the minimum necessary to retrieve the token.
#   - No update, delete, or list capabilities are granted.
#   - Ensure this policy is applied with Vault’s principle of least
#     privilege in mind.
# -------------------------------------------------------------------

path "secret/data/github-token" {
  capabilities = ["read"]
}
