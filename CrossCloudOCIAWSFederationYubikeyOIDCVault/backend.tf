########################################
# backend.tf
# --------------------------------------
# Configures the remote backend on Terraform Cloud
# for storing state in a secure, managed location.
########################################

terraform {
  backend "remote" {
    hostname     = "app.terraform.io"
    organization = "my-org"

    workspaces {
      name = "cross-cloud-federation"
    }
  }
}
