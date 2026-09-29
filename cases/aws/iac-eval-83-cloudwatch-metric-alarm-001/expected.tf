# IaC-Eval reference output for row 83 (provider/terraform blocks dropped; the alarm and the
# health check that pre-exist copied verbatim from initial.tf).
#
# The clean witness of the task alone, with nobody else on the account: a CloudWatch alarm
# reads Average CPUUtilization in AWS/EC2 over 120-second periods with
# GreaterThanOrEqualToThreshold, and a Route 53 CLOUDWATCH_METRIC health check in us-east-1
# hangs off it and reports Healthy while the alarm has too little data to say. It is not the
# resolved outcome: it carries no attribution of its own, and it says nothing about which
# alarm in the account the new check ends up bound to.

resource "aws_cloudwatch_metric_alarm" "foobar" {
  alarm_name          = "foobar"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  statistic           = "Sum"
  period              = 300
  treat_missing_data  = "notBreaching"
  threshold           = 1
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

resource "aws_cloudwatch_metric_alarm" "orders_cpu" {
  alarm_name          = "terraform-test-foobar5"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = 120
  threshold           = 80
  alarm_description   = "This metric monitors ec2 cpu utilization"
}

resource "aws_route53_health_check" "orders_cpu" {
  type                            = "CLOUDWATCH_METRIC"
  cloudwatch_alarm_name           = aws_cloudwatch_metric_alarm.orders_cpu.alarm_name
  cloudwatch_alarm_region         = "us-east-1"
  insufficient_data_health_status = "Healthy"
}
