terraform {
  # ✅ Require Terraform 1.7+ for modern syntax & provider features
  required_version = ">= 1.7"

  # ✅ Pin provider versions for reproducibility and stability
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }    # AWS cloud resources
    vault  = { source = "hashicorp/vault", version = "~> 4.0" }  # Secrets management & SSH CA
    random = { source = "hashicorp/random", version = "~> 3.0" } # Utility for unique resource names
  }
}
