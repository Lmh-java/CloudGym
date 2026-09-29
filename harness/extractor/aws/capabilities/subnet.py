"""Capability adapter for ``aws_subnet``."""

from .base import CapabilityAdapter


class SubnetAdapter(CapabilityAdapter):
    terraform_type = "aws_subnet"
    cloudcontrol_type = "AWS::EC2::Subnet"
    semantic_properties = (
        "CidrBlock",
        "VpcId",  # rewritten to a logical address during normalization
        "MapPublicIpOnLaunch",
        "Tags",
    )
    volatile_fields = (
        "SubnetId",
        # Region-agnostic seeds never pin an AZ, so the runtime-chosen zone
        # is noise; an AZ-pinning capability would need its own adapter.
        "AvailabilityZone",
        "AvailabilityZoneId",
        "NetworkAclAssociationId",
        "Ipv6CidrBlocks",
    )
    readiness_properties = ("SubnetId", "CidrBlock", "VpcId")
