"""Capability adapter for ``aws_iam_role_policy_attachment``.

Managed-policy attachments are the ``ManagedPolicyArns`` property of
``AWS::IAM::Role``; the attachment is a projection of the role and never
binds an identifier of its own.
"""

from .iam_role import IamRoleAdapter


class IamRolePolicyAttachmentAdapter(IamRoleAdapter):
    terraform_type = "aws_iam_role_policy_attachment"
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        raise ValueError(
            f"{self.terraform_type} is a projection of its role; bind the role instead")
