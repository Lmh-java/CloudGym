"""Capability adapter for ``aws_eip``.

Added 2026-09-23 (row 392; ec2 already allowlisted). Cloud Control ``AWS::EC2::EIP`` is
identified by ``<public ip>|<allocation id>``; Terraform's id is the allocation id, so the
binding joins ``public_ip`` and ``id``. The association (instance or network interface) is
semantic: it is what another principal's move of the address changes.
"""

from .base import CapabilityAdapter


class EipAdapter(CapabilityAdapter):
    terraform_type = "aws_eip"
    cloudcontrol_type = "AWS::EC2::EIP"
    semantic_properties = ("Domain", "InstanceId", "NetworkBorderGroup", "PublicIpv4Pool", "Tags")
    volatile_fields = ("AllocationId", "PublicIp")
    readiness_properties = ("AllocationId", "PublicIp")

    def identifier_from_state(self, attributes: dict) -> str:
        ip, alloc = attributes.get("public_ip"), attributes.get("id") or attributes.get("allocation_id")
        if not ip or not alloc:
            raise ValueError(f"{self.terraform_type}: state instance lacks public_ip / id")
        return f"{ip}|{alloc}"

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier.split("|", 1)[1]], Tags=tags)
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}
