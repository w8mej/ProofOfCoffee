##########################################
# eventbridge.tf
# Purpose: Trigger the Lambda every 20 minutes to rotate credentials
# Status: PROOF OF CONCEPT – NOT FOR PRODUCTION
##########################################
#########################
# Security & Ops notes (PoC)
#No DLQ or retry policy is configured on the trigger; failures rely on Lambda’s own retry.
#Production: add an EventBridge DLQ (SNS/SQS) and alerting.
#If rotations must be serialized, consider reserved concurrency = 1 on the Lambda to prevent overlap.

#Tunables
#schedule_expression: swap to cron() if you need deterministic wall-clock times.
#########################

# CloudWatch Event Rule to schedule every 20 minutes
# NOTE: For deterministic timing, cron() could be used instead of rate()
resource "aws_cloudwatch_event_rule" "every_20m" {
  name                = "${var.name}-rotate-credential-20m"
  schedule_expression = "rate(20 minutes)"
}

# Target: The rotation Lambda function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.every_20m.name
  target_id = "lambda"
  arn       = aws_lambda_function.rotate.arn
}

# Permission for EventBridge to invoke the Lambda
# Security: Scoped only to this specific rule's ARN
resource "aws_lambda_permission" "allow_events" {
  statement_id  = "AllowEvent"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.every_20m.arn
}
