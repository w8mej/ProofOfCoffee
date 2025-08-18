########################################
# backend.tf
# --------------------------------------
# Configures the remote backend on Terraform Cloud
# for storing state in a secure, managed location.
########################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"
  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "my-org"

    workspaces {
      name = "cross-cloud-federation"
    }
  }
}
