"""Capability adapter for ``aws_iam_role``."""

from .base import CapabilityAdapter


class IamRoleAdapter(CapabilityAdapter):
    terraform_type = "aws_iam_role"
    cloudcontrol_type = "AWS::IAM::Role"
    semantic_properties = (
        "AssumeRolePolicyDocument",
        "Description",
        "ManagedPolicyArns",
        "MaxSessionDuration",
        "Path",
        "PermissionsBoundary",
        "Policies",
        "Tags",
    )
    volatile_fields = (
        # RoleName is generated when Terraform name/name_prefix is omitted.
        "RoleName",
        "Arn",
        "RoleId",
    )
    readiness_properties = ("RoleName", "RoleId")
