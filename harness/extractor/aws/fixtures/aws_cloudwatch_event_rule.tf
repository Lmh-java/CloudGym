resource "aws_cloudwatch_event_rule" "capability" {
  name_prefix         = "cloudgym-capability-"
  schedule_expression = "rate(1 day)"
  state               = "DISABLED"
}
