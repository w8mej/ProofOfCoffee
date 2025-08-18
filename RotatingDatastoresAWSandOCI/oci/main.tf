##########################################
# main.tf
# Purpose: Provider pinning and configuration
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Pins the OCI provider to a stable major version and declares the provider.
#
# Security & Ops notes (PoC):
# - No remote backend is set here. Production: configure a remote backend
#   with state encryption and locking (e.g., OCI Object Storage + lock mechanism).
#
# Tunables:
# - Lock the exact provider version if your environment demands repeatable plan/apply.
##########################################

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 6.0"
    }
  }
}

provider "oci" {}
