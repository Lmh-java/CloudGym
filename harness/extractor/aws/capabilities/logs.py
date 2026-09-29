"""Capability adapters for CloudWatch Logs: log groups and the account's
resource policies. Both list region-wide; identifiers are the names, which
are also Terraform's ids.
"""

import json

from .base import CapabilityAdapter


class LogGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_cloudwatch_log_group"
    cloudcontrol_type = "AWS::Logs::LogGroup"
    semantic_properties = (
        "DataProtectionPolicy",
        "FieldIndexPolicies",
        "KmsKeyId",
        "LogGroupClass",
        "LogGroupName",
        "RetentionInDays",
        "Tags",
    )
    volatile_fields = ("Arn",)
    readiness_properties = ("LogGroupName", "Arn")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        session.client("logs").put_retention_policy(logGroupName=identifier, retentionInDays=3)
        return {"RetentionInDays": 3}


class LogResourcePolicyAdapter(CapabilityAdapter):
    terraform_type = "aws_cloudwatch_log_resource_policy"
    cloudcontrol_type = "AWS::Logs::ResourcePolicy"
    semantic_properties = ("PolicyName", "PolicyDocument")
    volatile_fields = ()
    readiness_properties = ("PolicyName", "PolicyDocument")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        raw = properties.get("PolicyDocument")
        document = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
        statements = list(document.get("Statement") or [])
        statements.append({
            "Sid": "CloudGymSmokeMutation", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "logs:PutLogEvents",
            "Resource": "arn:aws:logs:*:*:log-group:/aws/events/cloudgym-smoke:*",
        })
        document = {"Version": document.get("Version", "2012-10-17"), "Statement": statements}
        session.client("logs").put_resource_policy(policyName=identifier, policyDocument=json.dumps(document))
        # The handler returns PolicyDocument as the string it stored: compare canonically.
        return {"PolicyDocument": json.dumps(document)}

    def project(self, properties: dict) -> dict:
        projected = super().project(properties)
        raw = projected.get("PolicyDocument")
        if isinstance(raw, str):
            try:
                projected["PolicyDocument"] = json.dumps(json.loads(raw))
            except ValueError:
                pass
        return projected
