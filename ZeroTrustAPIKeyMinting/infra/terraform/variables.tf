###############################################################################
# Terraform Variables — OCI MPC Minting Deployment
#
# Purpose
# - Centralizes all configurable parameters for the deployment.
# - Separates credentials, network, compute, and encryption settings from code.
#
# Security & Ops Notes
# - **Never** hardcode sensitive values (OCIDs, keys) here—pass via `terraform.tfvars` 
#   or environment variables, or use Vault/SSM.
# - Keep `allow_cidr` restrictive (never `0.0.0.0/0`), especially for SSH and RPC ports.
# - Consider using instance principals for automation instead of `user_ocid` + API keys.
# - Default values provided are for development; production deployments should review
#   shape, OCPUs, memory, and encryption requirements.
#
# Tunables
# - `instance_shape`, `ocpus`, `memory_gbs` — adjust to workload needs.
# - `kms_key_ocid` — set for Object Storage SSE with KMS; null disables it.
###############################################################################

variable "tenancy_ocid" {
  description = "OCI Tenancy OCID"
  type        = string
}

variable "user_ocid" {
  description = "User OCID used for CLI auth (if not using instance principals)"
  type        = string
}

variable "fingerprint" {
  description = "API key fingerprint for CLI auth"
  type        = string
}

variable "private_key_path" {
  description = "Path to the private API key (CLI auth)"
  type        = string
}

variable "region" {
  description = "OCI region"
  type        = string
  default     = "us-phoenix-1"
}

variable "compartment_ocid" {
  description = "Target compartment OCID"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key to provision on instances"
  type        = string
}

variable "display_name" {
  description = "Base display name for resources"
  type        = string
  default     = "mpc-minting-cvm"
}

variable "instance_shape" {
  description = "Compute shape to use for instances"
  type        = string
  default     = "VM.Standard.E4.Flex"
}

variable "ocpus" {
  description = "OCPUs for flexible shape"
  type        = number
  default     = 2
}

variable "memory_gbs" {
  description = "Memory in GBs for flexible shape"
  type        = number
  default     = 16
}

variable "subnet_cidr" {
  description = "Primary Subnet CIDR"
  type        = string
  default     = "10.10.0.0/24"
}

variable "allow_cidr" {
  description = "CIDR allowed to access instances (never 0.0.0.0/0)"
  type        = string
  default     = "10.0.0.0/8"
}

variable "image_ocid" {
  description = "Image OCID for instances/OKE nodes"
  type        = string
}

variable "kms_key_ocid" {
  description = "OCI KMS key OCID for Object Storage server-side encryption"
  type        = string
  default     = null
}
