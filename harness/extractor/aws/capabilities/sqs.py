"""Capability adapter for ``aws_sqs_queue``.

Added 2026-09-23 (sqs already allowlisted). Read through Cloud Control
(``AWS::SQS::Queue``), whose identifier is the queue URL, which is also Terraform's id.
SQS applies attribute changes eventually (up to about a minute), so the smoke's
converged-read check matters here. The refusal catalogue's ``sqs.queue`` entry (a queue
deleted by another principal cannot be recreated under its name for 60 seconds) makes it
an execution-conflict resource as well.

The queue listing (Cloud Control LIST, backed by ListQueues) is eventually consistent both
ways, for up to about a minute (live smoke 2026-09-23): a new queue is missing from it, and a
deleted queue is still in it while GetResource already answers NotFound. The read is
authoritative, so a listed queue that reads NotFound is gone, and a queue created less than
``list_lag_s`` before a region-wide capture may be absent from it (bound queues are read by
URL and unaffected).
"""

from .base import CapabilityAdapter


class SqsQueueAdapter(CapabilityAdapter):
    terraform_type = "aws_sqs_queue"
    cloudcontrol_type = "AWS::SQS::Queue"
    semantic_properties = (
        "ContentBasedDeduplication",
        "DeduplicationScope",
        "DelaySeconds",
        "FifoQueue",
        "FifoThroughputLimit",
        "KmsDataKeyReusePeriodSeconds",
        "KmsMasterKeyId",
        "MaximumMessageSize",
        "MessageRetentionPeriod",
        "QueueName",
        "ReceiveMessageWaitTimeSeconds",
        "RedriveAllowPolicy",
        "RedrivePolicy",
        "SqsManagedSseEnabled",
        "Tags",
        "VisibilityTimeout",
    )
    volatile_fields = ("Arn", "QueueUrl")
    readiness_properties = ("QueueUrl", "Arn", "QueueName")
    list_lag_s = 90.0

    def tolerated_get_error(self, identifier: str, error: Exception) -> bool:
        return _not_found(error)

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        return _not_found(error)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        session.client("sqs").set_queue_attributes(QueueUrl=identifier, Attributes={"VisibilityTimeout": "77"})
        return {"VisibilityTimeout": 77}


def _not_found(error: Exception) -> bool:
    response = getattr(error, "response", None) or {}
    return (response.get("Error") or {}).get("Code") in ("ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue")
