# -------------------------------------------------------------------
# Terraform Configuration: YubiKey Onboarding to Kubernetes Namespace
# -------------------------------------------------------------------
# Purpose:
#   This configuration automates the onboarding of new employees by:
#     1. Looking up their identity in Vault using their YubiKey serial number.
#     2. Creating a dedicated Kubernetes namespace for that employee.
#
# Requirements:
#   - Terraform >= 1.5.0
#   - Access to Terraform Cloud with an existing organization & workspace.
#   - Vault configured with identity entities and aliases tied to YubiKey serials.
#   - A functional kubeconfig file with cluster admin privileges.
#
# Security Notes:
#   - Namespaces are prefixed with "emp-" and suffixed with Vault's entity ID.
#   - Vault’s identity service ensures the namespace is tied to an authenticated user.
#   - No hardcoded sensitive values are present; all secrets come from Vault.
# -------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  # Required providers and their versions
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }

  # Terraform Cloud backend configuration
  cloud {
    organization = "my-org" # Replace with your Terraform Cloud org name

    workspaces {
      name = "yubikey-onboard" # Workspace managing the onboarding workflow
    }
  }
}

# -------------------------------------------------------------------
# Kubernetes Provider
# -------------------------------------------------------------------
# Uses the local kubeconfig to authenticate and manage resources
# in the target Kubernetes cluster.
# -------------------------------------------------------------------
provider "kubernetes" {
  config_path = "~/.kube/config"
}

# -------------------------------------------------------------------
# Data Source: Vault Identity Entity
# -------------------------------------------------------------------
# Looks up the Vault identity entity for a new employee based on
# their YubiKey serial number. This serial should match an alias
# configured in Vault.
#
# Variable:
#   var.yubikey_serial – The serial number printed on the employee’s YubiKey.
# -------------------------------------------------------------------
data "vault_identity_entity" "new_employee" {
  alias_name = var.yubikey_serial
}

# -------------------------------------------------------------------
# Resource: Kubernetes Namespace for Employee
# -------------------------------------------------------------------
# Creates a Kubernetes namespace named "emp-<entity_id>", ensuring
# a unique and traceable namespace per onboarded employee.
# -------------------------------------------------------------------
resource "kubernetes_namespace" "employee" {
  metadata {
    name = "emp-${data.vault_identity_entity.new_employee.id}"
  }
}
