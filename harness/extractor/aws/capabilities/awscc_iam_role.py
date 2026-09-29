"""Capability adapter for ``awscc_iam_role``."""

from .iam_role import IamRoleAdapter


class AwsccIamRoleAdapter(IamRoleAdapter):
    """AWSCC and AWS provider roles share one Cloud Control model."""

    terraform_type = "awscc_iam_role"
