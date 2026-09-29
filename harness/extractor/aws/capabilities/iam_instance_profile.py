"""Capability adapter for ``aws_iam_instance_profile``."""

from .base import CapabilityAdapter


class IamInstanceProfileAdapter(CapabilityAdapter):
    terraform_type = "aws_iam_instance_profile"
    cloudcontrol_type = "AWS::IAM::InstanceProfile"
    semantic_properties = (
        "InstanceProfileName",
        "Path",
        "Roles",  # role names; rewritten to logical addresses during normalization
    )
    volatile_fields = ("Arn",)
    readiness_properties = ("InstanceProfileName", "Arn")
    # No smoke_mutation: the schema exposes no tags and a profile holds at most one
    # role, so the only writable change is removing that role — which the smoke's
    # own destroy then has to cope with. Left "unproven" on purpose.
