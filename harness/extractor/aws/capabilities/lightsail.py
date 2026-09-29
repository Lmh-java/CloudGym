"""Capability adapters for Lightsail: ``aws_lightsail_instance``, ``aws_lightsail_disk`` and
``aws_lightsail_disk_attachment``.

Added 2026-09-23 (rows 372-374). Needs ``lightsail:*`` in the sandbox SCP (with guardrails
against load balancers, databases, distributions, container services and domains); a
``nano`` bundle is about $0.005 an hour, so the family is left out of ``BILLABLE_TYPES``.
Cloud Control reads instances and disks by name (Terraform's id); the disk attachment is a
projection of the disk's ``AttachedTo`` / ``Path`` / ``IsAttached``. Instance and disk state
(pending, running, stopping; available, in-use) is semantic: another principal stopping an
instance or detaching a disk shows there.
"""

from .base import CapabilityAdapter


class LightsailInstanceAdapter(CapabilityAdapter):
    terraform_type = "aws_lightsail_instance"
    cloudcontrol_type = "AWS::Lightsail::Instance"
    semantic_properties = ("AddOns", "AvailabilityZone", "BlueprintId", "BundleId", "KeyPairName",
                           "Networking", "State", "Tags")
    volatile_fields = ("Hardware", "InstanceArn", "Ipv6Addresses", "IsStaticIp", "Location", "PrivateIpAddress",
                       "PublicIpAddress", "ResourceType", "SshKeyName", "SupportCode", "UserName")
    readiness_properties = ("InstanceName", "BundleId", "State")

    def project(self, properties: dict) -> dict:
        projected = super().project(properties)
        if isinstance(projected.get("State"), dict):
            projected["State"] = {"Name": projected["State"].get("Name")}
        if isinstance(projected.get("Networking"), dict):
            # MonthlyTransfer is the bundle's allowance, not configuration.
            projected["Networking"] = {k: v for k, v in projected["Networking"].items() if k != "MonthlyTransfer"}
        return projected

    def ready(self, properties: dict) -> bool:
        return super().ready(properties) and (properties.get("State") or {}).get("Name") not in ("pending",)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("lightsail").tag_resource(resourceName=identifier, tags=[{"key": "cloudgym-smoke",
                                                                                 "value": "mutation-visible"}])
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}


class LightsailDiskAdapter(CapabilityAdapter):
    terraform_type = "aws_lightsail_disk"
    cloudcontrol_type = "AWS::Lightsail::Disk"
    semantic_properties = ("AddOns", "AttachedTo", "AttachmentState", "AvailabilityZone", "IsAttached",
                           "Path", "SizeInGb", "State", "Tags")
    volatile_fields = ("DiskArn", "Iops", "Location", "ResourceType", "SupportCode")
    readiness_properties = ("DiskName", "SizeInGb", "State")

    def ready(self, properties: dict) -> bool:
        return super().ready(properties) and properties.get("State") not in ("pending",)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("lightsail").tag_resource(resourceName=identifier, tags=[{"key": "cloudgym-smoke",
                                                                                 "value": "mutation-visible"}])
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}


class LightsailDiskAttachmentAdapter(CapabilityAdapter):
    terraform_type = "aws_lightsail_disk_attachment"
    cloudcontrol_type = "AWS::Lightsail::Disk"
    standalone = False
    semantic_properties = ("AttachedTo", "IsAttached", "Path")
    readiness_properties = ("DiskName",)
