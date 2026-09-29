# Pre-existing: the account's one CloudWatch alarm and the one Route 53 health check that
# hangs off it. The alarm is literally named `foobar` — a placeholder name someone gave it
# long ago — but what it measures is the billing worker's Lambda error rate, and the health
# check that reports for the billing worker is bound to it. Both carry the account's
# attribution: an `Owner` and a `Workload` tag naming who they belong to.
#
# Nothing of the task exists at S0: no alarm anywhere in the account reads EC2 CPU
# utilization, and the only health check there reports Unhealthy when its alarm has too
# little data, not Healthy. The EC2 CPU alarm the task asks for and the check that reports
# on it are absent in both directions.

resource "aws_cloudwatch_metric_alarm" "foobar" {
  alarm_name          = "foobar"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_description   = "Billing worker error rate; the on-call runbook watches this alarm"

  dimensions = {
    FunctionName = "billing-worker"
  }

  tags = {
    Owner    = "platform-oncall"
    Workload = "billing-worker"
  }
}

resource "aws_route53_health_check" "billing_worker" {
  type                            = "CLOUDWATCH_METRIC"
  cloudwatch_alarm_name           = aws_cloudwatch_metric_alarm.foobar.alarm_name
  cloudwatch_alarm_region         = "us-east-1"
  insufficient_data_health_status = "Unhealthy"

  tags = {
    Name     = "billing-worker-errors"
    Owner    = "platform-oncall"
    Workload = "billing-worker"
  }
}
