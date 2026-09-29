"""Capability adapter for ``aws_sns_topic``."""

from .base import CapabilityAdapter


class SnsTopicAdapter(CapabilityAdapter):
    terraform_type = "aws_sns_topic"
    cloudcontrol_type = "AWS::SNS::Topic"
    semantic_properties = (
        "ArchivePolicy",
        "ContentBasedDeduplication",
        "DataProtectionPolicy",
        "DeliveryStatusLogging",
        "DisplayName",
        "FifoThroughputScope",
        "FifoTopic",
        "KmsMasterKeyId",
        "SignatureVersion",
        "Subscription",
        "Tags",
        "TopicName",
        "TracingConfig",
    )
    volatile_fields = ("TopicArn",)
    readiness_properties = ("TopicArn", "TopicName")
