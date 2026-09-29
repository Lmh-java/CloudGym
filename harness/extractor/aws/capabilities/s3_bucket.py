"""Capability adapter for ``aws_s3_bucket``."""

from .base import CapabilityAdapter


class S3BucketAdapter(CapabilityAdapter):
    terraform_type = "aws_s3_bucket"
    cloudcontrol_type = "AWS::S3::Bucket"
    semantic_properties = (
        "AbacStatus",
        "AccelerateConfiguration",
        # AccessControl is write-only in the CloudFormation schema, but keep
        # it in the allowlist so it is preserved if the read handler exposes
        # it in a future schema version.
        "AccessControl",
        "AnalyticsConfigurations",
        "BucketEncryption",
        "CorsConfiguration",
        "IntelligentTieringConfigurations",
        "InventoryConfigurations",
        "LifecycleConfiguration",
        "LoggingConfiguration",
        "MetadataConfiguration",
        "MetricsConfigurations",
        "NotificationConfiguration",
        "ObjectLockConfiguration",
        "ObjectLockEnabled",
        "OwnershipControls",
        "PublicAccessBlockConfiguration",
        "ReplicationConfiguration",
        "Tags",
        "VersioningConfiguration",
        "WebsiteConfiguration",
    )
    volatile_fields = (
        # BucketName is the Cloud Control identifier.  Terraform may generate
        # it from bucket_prefix, so retaining it would make an otherwise
        # equivalent destroy/recreate reset compare unequal.
        "BucketName",
        "Arn",
        "DomainName",
        "DualStackDomainName",
        "RegionalDomainName",
        "WebsiteURL",
    )
    readiness_properties = ("BucketName",)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        """Out-of-band tag write; capture must show it (live false-negative proof)."""
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("s3").put_bucket_tagging(
            Bucket=identifier, Tagging={"TagSet": [{"Key": t["Key"], "Value": t["Value"]} for t in tags]})
        return {"Tags": tags}
