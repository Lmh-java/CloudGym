"""Capability adapter for ``aws_kinesisanalyticsv2_application`` (Managed Service for Apache Flink).

Added 2026-09-23 (rows 58, 73). Needs ``kinesisanalytics:*`` in the sandbox SCP; an
application is billed per KPU-hour only while RUNNING, so a created, stopped one is free
(left out of ``BILLABLE_TYPES``). Cloud Control reads it by name; Terraform's id is the ARN,
so the binding is on ``name``. ``ApplicationStatus`` (READY, STARTING, RUNNING, UPDATING,
...) is not in Cloud Control's read: the refusal catalogue observes it natively.
"""

from .base import CapabilityAdapter


class KinesisAnalyticsV2ApplicationAdapter(CapabilityAdapter):
    terraform_type = "aws_kinesisanalyticsv2_application"
    cloudcontrol_type = "AWS::KinesisAnalyticsV2::Application"
    semantic_properties = ("ApplicationConfiguration", "ApplicationDescription", "ApplicationMaintenanceConfiguration",
                           "ApplicationMode", "ApplicationName", "RuntimeEnvironment", "ServiceExecutionRole", "Tags")
    volatile_fields = ()
    readiness_properties = ("ApplicationName", "RuntimeEnvironment")

    def identifier_from_state(self, attributes: dict) -> str:
        name = attributes.get("name")
        if not name:
            raise ValueError(f"{self.terraform_type}: state instance has no 'name'")
        return name

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        ka = session.client("kinesisanalyticsv2")
        arn = ka.describe_application(ApplicationName=identifier)["ApplicationDetail"]["ApplicationARN"]
        ka.tag_resource(ResourceARN=arn, Tags=tags)
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}
