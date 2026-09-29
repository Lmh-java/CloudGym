"""Capability adapter for ``aws_dynamodb_table``.

An on-demand (PAY_PER_REQUEST) table with no traffic costs storage only —
deliberately not in BILLABLE_TYPES. Cloud Control fully supports the type.
"""

from .base import CapabilityAdapter


class DynamoDbTableAdapter(CapabilityAdapter):
    terraform_type = "aws_dynamodb_table"
    cloudcontrol_type = "AWS::DynamoDB::Table"
    semantic_properties = (
        "AttributeDefinitions",
        "BillingMode",
        "DeletionProtectionEnabled",
        "GlobalSecondaryIndexes",
        "KeySchema",
        "LocalSecondaryIndexes",
        "PointInTimeRecoverySpecification",
        "ProvisionedThroughput",
        "SSESpecification",
        "StreamSpecification",
        "TableClass",
        "TableName",
        "Tags",
        "TimeToLiveSpecification",
    )
    volatile_fields = ("Arn", "StreamArn")
    readiness_properties = ("TableName", "Arn")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        arn = properties.get("Arn")
        if not arn:
            return None
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("dynamodb").tag_resource(ResourceArn=arn, Tags=tags)
        return {"Tags": tags}
