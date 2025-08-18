# -----------------------------------------------------------------------------
# File: terraform/oci/variables.tf
# What it does:
#   Declares all variables needed to launch OCI CVMs and pull signed images.
# -----------------------------------------------------------------------------
variable "tenancy_ocid" {
  type = string
  validation {
    condition     = startswith(var.tenancy_ocid, "ocid1.")
    error_message = "tenancy_ocid must start with 'ocid1.'."
  }
}

variable "user_ocid" {
  type = string
  validation {
    condition     = startswith(var.user_ocid, "ocid1.")
    error_message = "user_ocid must start with 'ocid1.'."
  }
}

variable "fingerprint" {
  type = string
  validation {
    # Accepts OCI's colon-separated hex (SHA1, e.g., '20:3b:...') or plain hex
    condition     = can(regex("^([0-9a-f]{2}:){19}[0-9a-f]{2}$", lower(var.fingerprint))) || can(regex("^[0-9a-f]{40}$", lower(var.fingerprint)))
    error_message = "fingerprint must be a 40-hex SHA1 (with or without colons)."
  }
}

variable "private_key_path" {
  type = string
  validation {
    condition     = length(trim(var.private_key_path)) > 0
    error_message = "private_key_path must be a non-empty path."
  }
}

variable "region" {
  type = string
  validation {
    # Generic OCI region format like 'us-ashburn-1'
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d+$", var.region))
    error_message = "region must look like 'us-ashburn-1'."
  }
}

variable "compartment_ocid" {
  type = string
  validation {
    condition     = startswith(var.compartment_ocid, "ocid1.")
    error_message = "compartment_ocid must start with 'ocid1.'."
  }
}

variable "subnet_ocid" {
  type = string
  validation {
    condition     = startswith(var.subnet_ocid, "ocid1.")
    error_message = "subnet_ocid must start with 'ocid1.'."
  }
}

variable "shape" {
  type = string
  validation {
    condition     = length(trim(var.shape)) > 0
    error_message = "shape must be non-empty (e.g., 'VM.Standard3.Flex')."
  }
}

variable "image_ocid" {
  type = string
  validation {
    condition     = startswith(var.image_ocid, "ocid1.")
    error_message = "image_ocid must start with 'ocid1.'."
  }
}

variable "registry" {
  type    = string
  default = "ghcr.io"
  validation {
    # Simple hostname/registry check
    condition     = can(regex("^[a-z0-9.-]+(?::\\d+)?$", var.registry))
    error_message = "registry must be a hostname (optionally with :port), e.g., 'ghcr.io' or 'registry.example.com:5000'."
  }
}

variable "image_repo" {
  type        = string
  description = "e.g., org/repo"
  validation {
    # org/repo, lowercase + dashes/underscores/dots
    condition     = can(regex("^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$", var.image_repo))
    error_message = "image_repo must look like 'org/repo' (lowercase, digits, dot, dash, underscore)."
  }
}

variable "image_tag" {
  type    = string
  default = "latest"
  validation {
    # allow 'latest' or (optional 'v') semver with optional pre-release/build
    condition     = can(regex("^latest$|^v?\\d+\\.\\d+\\.\\d+(?:[-+][A-Za-z0-9._-]+)?$", var.image_tag))
    error_message = "image_tag must be 'latest' or a semver like '1.2.3' or 'v1.2.3-beta.1'."
  }
}

variable "tee_policy_hash" {
  type        = string
  description = "hex SHA-256 policy hash"
  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.tee_policy_hash))
    error_message = "tee_policy_hash must be a 64-char hex (SHA-256) string."
  }
}
