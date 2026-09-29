"""Capability adapter for ``aws_iam_policy`` (customer managed policies).

Cloud Control facts: AWS::IAM::ManagedPolicy's LIST handler enumerates every
AWS-managed policy too (~1200 of them), so discovery is native —
``iam:ListPolicies(Scope="Local")`` returns exactly the account's customer
managed policies in one call; envelopes still come verbatim from GetResource.
"""

from .base import CapabilityAdapter


class IamPolicyAdapter(CapabilityAdapter):
    terraform_type = "aws_iam_policy"
    cloudcontrol_type = "AWS::IAM::ManagedPolicy"
    semantic_properties = (
        "Description",
        "Groups",
        "Path",
        "PolicyDocument",
        "Roles",
        "Users",
    )
    volatile_fields = (
        # ManagedPolicyName is generated when Terraform name/name_prefix is omitted.
        "ManagedPolicyName",
        "PolicyArn",
        "PolicyId",
        "AttachmentCount",
        "CreateDate",
        "UpdateDate",
        "DefaultVersionId",
        "IsAttachable",
        "PermissionsBoundaryUsageCount",
    )
    readiness_properties = ("PolicyArn", "PolicyId")

    def native_list(self, session, region: str) -> list[str]:
        iam = session.client("iam")
        arns: list[str] = []
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            arns.extend(p["Arn"] for p in page.get("Policies", []))
        return arns

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        document = dict(properties.get("PolicyDocument") or {})
        statements = list(document.get("Statement") or [])
        statements.append({"Sid": "CloudGymSmokeMutation", "Effect": "Allow",
                           "Action": "ec2:DescribeVpcs", "Resource": "*"})
        document = {"Version": document.get("Version", "2012-10-17"), "Statement": statements}
        import json
        session.client("iam").create_policy_version(
            PolicyArn=identifier, PolicyDocument=json.dumps(document), SetAsDefault=True)
        return {"PolicyDocument": document}
