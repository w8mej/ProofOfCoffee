##########################################
# object_storage.tf
# Purpose: Create an audit bucket for rotation events (cold storage)
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Creates a versioned Object Storage bucket in Archive tier for write-once audit records
#   (HMAC-only payloads; never plaintext secrets).
#
# Security & Ops notes (PoC):
# - No explicit bucket policy or encryption settings here.
#   Production: enforce SSE (KMS), pre-authenticated requests with short TTL if used,
#   object lock/retention if compliance requires WORM, and explicit deny of public access.
#
# Tunables:
# - storage_tier can be "Standard" then lifecycle to "Archive" if you query recent logs often.
# - versioning can be paired with retention policies in regulated environments.
##########################################

resource "oci_objectstorage_bucket" "audit" {
  name           = "${var.name}-rotation-audit"
  compartment_id = var.compartment_ocid
  namespace      = var.os_namespace
  storage_tier   = "Archive" # Cold storage; lowest cost, high retrieval latency
  versioning     = "Enabled" # Tamper-evidence and recovery
}
