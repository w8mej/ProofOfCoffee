##########################################
# events.tf
# Purpose: Schedule OCI Functions to run every 20 minutes and rotate credentials
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
#
# What this code does:
# - Creates an OCI Events scheduled rule (cron 0/20) that invokes the rotation Function.
#
# Security & Ops notes (PoC):
# - No DLQ/retry routing is defined here; failures rely on Function retry behavior/logs.
#   Production: add monitoring/alarms on function errors and consider a queue-based pattern.
# - Rule is scoped to the provided compartment for least privilege.
#
# Tunables:
# - Change cron() for cadence; e.g., "cron(0 0/1 * * ? *)" for hourly.
# - Toggle is_enabled for quick pausing.
##########################################

resource "oci_events_rule" "every_20m" {
  display_name   = "${var.name}-rotate-credential-20m"
  compartment_id = var.compartment_ocid
  is_enabled     = true

  # Cron expression: every 20 minutes
  condition = jsonencode({
    "eventType" : "com.oraclecloud.scheduled",
    "data" : { "schedule" : "cron(0/20 * * * ? *)" }
  })

  actions {
    actions {
      action_type = "FAAS" # Invoke an OCI Function
      is_enabled  = true
      function_id = oci_functions_function.rotate.id
    }
  }
}
