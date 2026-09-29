resource "aws_sns_topic" "capability" {
  name_prefix = "cloudgym-capability-"
}

resource "aws_cloudwatch_event_rule" "capability" {
  name_prefix         = "cloudgym-capability-"
  schedule_expression = "rate(1 day)"
  state               = "DISABLED"
}

resource "aws_cloudwatch_event_target" "capability" {
  rule = aws_cloudwatch_event_rule.capability.name
  arn  = aws_sns_topic.capability.arn
}
