# -----------------------------------------------------------------------------
# File: terraform/oci/variables.tf
# What it does:
#   Declares all variables needed to launch OCI CVMs and pull signed images.
# -----------------------------------------------------------------------------
variable "tenancy_ocid"     { type = string }
variable "user_ocid"        { type = string }
variable "fingerprint"      { type = string }
variable "private_key_path" { type = string }
variable "region"           { type = string }

variable "compartment_ocid" { type = string }
variable "subnet_ocid"      { type = string }

variable "shape"            { type = string }
variable "image_ocid"       { type = string }

variable "registry"         { type = string  default = "ghcr.io" }
variable "image_repo"       { type = string  description = "e.g., org/repo" }
variable "image_tag"        { type = string  default = "latest" }

variable "tee_policy_hash"  { type = string  description = "hex SHA-256 policy hash" }
