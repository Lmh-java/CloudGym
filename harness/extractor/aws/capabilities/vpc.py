"""Capability adapter for ``aws_vpc``."""

from .base import CapabilityAdapter


class VpcAdapter(CapabilityAdapter):
    terraform_type = "aws_vpc"
    cloudcontrol_type = "AWS::EC2::VPC"
    semantic_properties = (
        "CidrBlock",
        "EnableDnsHostnames",
        "EnableDnsSupport",
        "InstanceTenancy",
        "Tags",
    )
    volatile_fields = (
        "VpcId",
        "CidrBlockAssociations",
        "DefaultNetworkAcl",
        "DefaultSecurityGroup",
        "Ipv6CidrBlocks",
    )
    readiness_properties = ("VpcId", "CidrBlock")
