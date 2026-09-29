"""Capability adapter for ``aws_iam_role_policy`` (inline role policies).

A projection of ``AWS::IAM::Role``: inline policies are the role document's
``Policies`` list, so the role binding already reads them. (The standalone
``AWS::IAM::RolePolicy`` type exists but has no LIST handler.)
"""

from .iam_role import IamRoleAdapter


class IamRolePolicyAdapter(IamRoleAdapter):
    terraform_type = "aws_iam_role_policy"
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        # Terraform's id is "<role>:<policy name>"; the role name is the Cloud Control id.
        role = attributes.get("role")
        if not role or not isinstance(role, str):
            raise ValueError(f"{self.terraform_type}: state instance has no role")
        return role
