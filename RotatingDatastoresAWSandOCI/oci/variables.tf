##########################################
# variables.tf
# Purpose: Inputs for naming, compartment/network wiring, and cross-cloud IDs
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Declares core inputs: compartment, subnet, image location, namespace, secret names,
#   and AWS secret ARNs to let the OCI worker read/write the AWS side (local-latency pattern).
#
# Security & Ops notes (PoC):
# - aws_secret_id / aws_conn_blob_secret_id are ARNs used only for worker config; they are not fetched here.
#   Keep them as parameters and store the real ARNs in CI secrets / tfvars.
#
# Tunables:
# - Change default secret names to match your naming conventions.
# - Split variables by environment (dev/stage/prod) with tfvars files.
##########################################

variable "name" { type = string default = "rotator" }

variable "compartment_ocid" { type = string }  # Target compartment for all OCI resources
variable "subnet_ocid"      { type = string }  # Private subnet for Functions app (egress required)
variable "ocir_image_uri"   { type = string }  # phx.ocir.io/<ns>/rotator:<tag>
variable "os_namespace"     { type = string }  # Object Storage namespace

variable "oci_secret_name"            { type = string default = "multi-cloud/app_user" }
variable "oci_conn_blob_secret_name"  { type = string default = "multi-cloud/app_connection_blob" }

# AWS ARNs passed to the worker so it can read/write local AWS Secrets Manager (latency-friendly)
variable "aws_secret_id"          { type = string }  # ARN, for worker env (credentials secret)
variable "aws_conn_blob_secret_id"{ type = string }  # ARN, for worker env (connection blob secret)
