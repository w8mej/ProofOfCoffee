############################################
# Unwrap the response-wrapped secret_id
# - Executes once per new wrapped token.
# - Writes JSON to a local file for consumption.
############################################
resource "null_resource" "unwrap_secret_id" {
  provisioner "local-exec" {
    command = <<EOT
      vault unwrap -format=json ${var.wrapped_token} > secret_id.json
    EOT
    environment = {
      VAULT_ADDR = "http://127.0.0.1:8200"
    }
  }

  # Ensure re-run when the input wrapped token changes
  triggers = {
    wrapped = var.wrapped_token
  }
}

############################################
# Read the unwrapped JSON into Terraform
############################################
data "local_file" "secret_id" {
  filename   = "${path.module}/secret_id.json"
  depends_on = [null_resource.unwrap_secret_id]
}

############################################
# Materialize the secret_id for provider login
# - Feeds the AppRole login block (Example 3).
# - Avoids printing secret_id to stdout.
############################################
resource "vault_generic_secret" "secret_id" {
  path      = "auth/approle/role/terraform-db/secret-id"
  data_json = data.local_file.secret_id.content
}
