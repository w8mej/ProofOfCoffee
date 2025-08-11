# -----------------------------------------------------------------------------
# OCI Functions Proof of Concept:
# Deploys a function to Oracle Cloud Infrastructure that uses a Vault-issued,
# short-lived TLS certificate as part of a secure invocation flow.
#
# Security Intent:
# - Each function version gets a unique, single-use cert issued by Vault PKI.
# - Cert is scoped via CN to the OCI Functions FQDN for that deployment.
# - TTL kept short (10m) to reduce key exposure if compromised.
#
# Caveats for Production:
# - In a real deployment, store TLS private keys in OCI Vault/KMS secrets,
#   not in plain Terraform config nor passed as an environment variable.
# - Add chain validation and revocation handling inside the function.
# - Use policy-bound Vault PKI roles to prevent misuse of the cert issuance.
# -----------------------------------------------------------------------------

# Create an OCI Functions Application as a container for the function.
resource "oci_functions_application" "app" {
  compartment_id = var.compartment_id
  display_name   = "yubi-secure-app" # Human-friendly app name for OCI Console.
}

# Deploy the actual OCI Function.
resource "oci_functions_function" "fn" {
  application_id     = oci_functions_application.app.id
  display_name       = "secure-fn"        # Name shown in OCI Console.
  image              = var.function_image # Pre-built Docker image in OCIR.
  memory_in_mbs      = 128                # Minimal memory footprint.
  timeout_in_seconds = 30                 # Short timeout for fast-exit logic.

  # Environment variables passed into the running function.
  # Here, we inject a Vault-issued TLS cert + private key at deploy time.
  config {
    TLS_CERT = vault_pki_secret_backend_cert.function_cert.certificate
    TLS_KEY  = vault_pki_secret_backend_cert.function_cert.private_key
  }
}

# Issue a short-lived, function-scoped TLS certificate from Vault PKI.
resource "vault_pki_secret_backend_cert" "function_cert" {
  backend              = vault_mount.yubisign_ca.path         # Vault PKI backend path.
  name                 = "fn-${oci_functions_function.fn.id}" # Vault role.
  common_name          = "fn-${oci_functions_function.fn.id}.functions.${var.region}.oci.oraclecloud.com"
  ttl                  = "10m" # Very short TTL for minimal exposure.
  private_key_format   = "pem" # Easy integration into app config.
  exclude_cn_from_sans = true  # CN-only cert to reduce SAN surface.
}
