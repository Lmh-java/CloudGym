resource "aws_cloudwatch_metric_alarm" "capability" {
  alarm_name          = "cloudgym-capability-check"
  alarm_description   = "CloudGym extractor capability check"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CapabilityCheck"
  namespace           = "CloudGym/Extractor"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
}
