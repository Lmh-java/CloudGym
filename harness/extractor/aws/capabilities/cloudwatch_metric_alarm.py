"""Capability adapter for ``aws_cloudwatch_metric_alarm``."""

from .base import CapabilityAdapter


class CloudWatchMetricAlarmAdapter(CapabilityAdapter):
    terraform_type = "aws_cloudwatch_metric_alarm"
    cloudcontrol_type = "AWS::CloudWatch::Alarm"
    semantic_properties = (
        "ActionsEnabled",
        "AlarmActions",
        "AlarmDescription",
        "AlarmName",
        "ComparisonOperator",
        "DatapointsToAlarm",
        "Dimensions",
        "EvaluateLowSampleCountPercentile",
        "EvaluationCriteria",
        "EvaluationInterval",
        "EvaluationPeriods",
        "EvaluationWindow",
        "ExtendedStatistic",
        "InsufficientDataActions",
        "MetricName",
        "Metrics",
        "Namespace",
        "OKActions",
        "Period",
        "Statistic",
        "Tags",
        "Threshold",
        "ThresholdMetricId",
        "TreatMissingData",
        "Unit",
    )
    volatile_fields = ("Arn",)
    readiness_properties = ("AlarmName", "Arn")
