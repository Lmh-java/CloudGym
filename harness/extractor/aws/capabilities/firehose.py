"""Capability adapter for ``aws_kinesis_firehose_delivery_stream``.

Added 2026-09-22 (13 IaC-Eval rows touch it). Reclassified out of ``BILLABLE_TYPES``: a
delivery stream is billed per GB ingested, so an idle stream costs nothing. Needs
``firehose:*`` in the sandbox SCP. Cloud Control identifies a stream by name; Terraform's
id is the ARN, so the adapter binds on ``name``. Creation takes one to two minutes, during
which ``UpdateDestination`` is refused with ``ResourceInUseException``: an execution-conflict
window in its own right.
"""

from .base import CapabilityAdapter


class FirehoseDeliveryStreamAdapter(CapabilityAdapter):
    terraform_type = "aws_kinesis_firehose_delivery_stream"
    cloudcontrol_type = "AWS::KinesisFirehose::DeliveryStream"
    semantic_properties = (
        "AmazonOpenSearchServerlessDestinationConfiguration",
        "AmazonopensearchserviceDestinationConfiguration",
        "DeliveryStreamEncryptionConfigurationInput",
        "DeliveryStreamName",
        "DeliveryStreamType",
        "ExtendedS3DestinationConfiguration",
        "HttpEndpointDestinationConfiguration",
        "KinesisStreamSourceConfiguration",
        "RedshiftDestinationConfiguration",
        "S3DestinationConfiguration",
        "SplunkDestinationConfiguration",
        "Tags",
    )
    volatile_fields = ("Arn",)
    readiness_properties = ("DeliveryStreamName", "Arn")

    def identifier_from_state(self, attributes: dict) -> str:
        name = attributes.get("name")
        if not name or not isinstance(name, str):
            raise ValueError(f"{self.terraform_type}: state instance has no 'name'")
        return name

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("firehose").tag_delivery_stream(DeliveryStreamName=identifier, Tags=tags)
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}
