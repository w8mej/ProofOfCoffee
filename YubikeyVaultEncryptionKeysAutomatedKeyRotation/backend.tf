terraform {
  # Configure Terraform's remote state backend to use Amazon S3.
  # This allows multiple team members or systems to share and lock state.
  backend "s3" {
    bucket = "my-terraform-state"     # S3 bucket where the state file is stored
    key    = "prod/terraform.tfstate" # Path/key for the state file in the bucket
    region = "us-east-1"              # AWS region where the bucket resides

    encrypt = false # 🔒 Disabled here for demo purposes.
    # NOTE: In production, enable S3 encryption 
    # (e.g., SSE-KMS) to protect sensitive state data.
    # Here we assume encryption will be handled manually.
  }
}
