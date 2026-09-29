"""Capability adapters for ``aws_instance`` and ``aws_key_pair``.

The sandbox SCP (``OnlyCheapInstanceTypes``) admits t2.micro / t3.micro /
t3.small only, so an instance is the one per-hour resource the bench allows;
fixtures and cases must terminate promptly.

``AWS::EC2::Instance`` is read natively. Its Cloud Control read handler calls
``ssm:ListAssociations`` (for the ``SsmAssociations`` property) and ssm is not
in the SCP allowlist, so every GetResource fails with AccessDenied (capability
smoke, 2026-09-08). Envelopes therefore carry the verbatim
``ec2:DescribeInstances`` instance document and semantic properties use its
field names. Terminated instances linger in DescribeInstances for about an
hour; they are reported as absent, matching the CloudFormation model.
"""

from datetime import datetime

from .base import CapabilityAdapter

_GONE_STATES = {"terminated"}
_TRANSITIONAL_STATES = {"pending", "shutting-down", "stopping"}


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


class InstanceAdapter(CapabilityAdapter):
    terraform_type = "aws_instance"
    cloudcontrol_type = "AWS::EC2::Instance"
    semantic_properties = (
        "BlockDeviceMappings",
        "EbsOptimized",
        "IamInstanceProfile",  # {"Arn", "Id"}; the ARN is rewritten to a logical address
        "ImageId",
        "InstanceType",
        "KeyName",
        "MetadataOptions",
        "Monitoring",
        "Placement",           # AvailabilityZone, Tenancy
        "RootDeviceName",
        "SecurityGroups",      # [{"GroupId", "GroupName"}]
        "SourceDestCheck",
        "SubnetId",            # rewritten to a logical address during normalization
        "Tags",
    )
    volatile_fields = (
        "InstanceId", "LaunchTime", "NetworkInterfaces", "PrivateDnsName", "PrivateIpAddress",
        "PublicDnsName", "PublicIpAddress", "State", "StateTransitionReason", "VpcId",
        "ClientToken", "UsageOperationUpdateTime",
    )
    readiness_properties = ("InstanceId", "ImageId", "InstanceType", "State")

    def _client(self, session, region: str):
        return session.client("ec2", region_name=region)

    @staticmethod
    def _live(instance: dict) -> bool:
        return (instance.get("State") or {}).get("Name") not in _GONE_STATES

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        for page in self._client(session, region).get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    if self._live(instance):
                        out.append((instance["InstanceId"], _jsonable(instance)))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        try:
            described = self._client(session, region).describe_instances(InstanceIds=[identifier])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
                return None
            raise
        instances = [i for r in described.get("Reservations", []) for i in r.get("Instances", [])]
        if not instances or not self._live(instances[0]):
            return None
        return _jsonable(instances[0])

    def ready(self, properties: dict) -> bool:
        if not super().ready(properties):
            return False
        return (properties.get("State") or {}).get("Name") not in _TRANSITIONAL_STATES

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier], Tags=tags)
        existing = [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"]
        return {"Tags": existing + tags}


class KeyPairAdapter(CapabilityAdapter):
    terraform_type = "aws_key_pair"
    cloudcontrol_type = "AWS::EC2::KeyPair"
    semantic_properties = ("KeyName", "KeyType", "KeyFormat", "Tags")
    volatile_fields = ("KeyPairId", "KeyFingerprint")
    readiness_properties = ("KeyName", "KeyPairId", "KeyFingerprint")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        key_pair_id = properties.get("KeyPairId")
        if not key_pair_id:
            return None
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[key_pair_id], Tags=tags)
        existing = [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"]
        return {"Tags": existing + tags}
