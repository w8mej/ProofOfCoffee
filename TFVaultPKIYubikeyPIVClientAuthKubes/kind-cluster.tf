# -------------------------------------------------------------------
# File: kind-cluster.tf
# -------------------------------------------------------------------
# Purpose:
#   Creates a local Kubernetes-in-Docker (KinD) cluster for demo and
#   testing purposes. This provides a safe, disposable environment
#   for Vault PKI certificate issuance and Kubernetes client access.
#
# Notes:
#   - KinD is used to spin up Kubernetes clusters inside Docker.
#   - Useful for local development, CI pipelines, and demos.
#   - Does not require cloud provider access.
# -------------------------------------------------------------------
resource "null_resource" "kind_cluster" {
  provisioner "local-exec" {
    command = <<EOT
      kind create cluster --name vault-pki-demo
    EOT
  }
}
