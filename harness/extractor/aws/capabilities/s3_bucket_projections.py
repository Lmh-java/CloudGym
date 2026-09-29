"""Terraform sub-resources of ``aws_s3_bucket`` that Cloud Control folds into
``AWS::S3::Bucket``: lifecycle rules, the public access block, the object lock
configuration, versioning, default encryption, ownership controls, access
logging, CORS, the website configuration, notifications, transfer
acceleration, and the per-name inventory / metrics / analytics /
intelligent-tiering configurations are all properties of the bucket document.

They are not standalone: the bucket binding already covers the resource, so
these adapters only widen the capture scope and never bind an identifier
of their own.

Deliberately absent: ``aws_s3_bucket_acl`` (``AccessControl`` is write-only in
the schema, so a capture can never witness it) and
``aws_s3_bucket_request_payment_configuration`` (not in the bucket schema).
"""

from .s3_bucket import S3BucketAdapter


class _S3BucketProjection(S3BucketAdapter):
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        # Terraform ids for these resources are "<bucket>" or
        # "<bucket>,<expected_bucket_owner>".
        identifier = super().identifier_from_state(attributes)
        return identifier.split(",", 1)[0]


class _S3BucketNamedProjection(S3BucketAdapter):
    """Per-name bucket configurations whose Terraform id is ``<bucket>:<name>``."""
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        identifier = super().identifier_from_state(attributes)
        return identifier.split(":", 1)[0]


class S3BucketLifecycleConfigurationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_lifecycle_configuration"


class S3BucketPublicAccessBlockAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_public_access_block"


class S3BucketObjectLockConfigurationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_object_lock_configuration"


class S3BucketVersioningAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_versioning"                      # VersioningConfiguration


class S3BucketServerSideEncryptionConfigurationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_server_side_encryption_configuration"  # BucketEncryption


class S3BucketOwnershipControlsAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_ownership_controls"              # OwnershipControls


class S3BucketLoggingAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_logging"                         # LoggingConfiguration


class S3BucketCorsConfigurationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_cors_configuration"              # CorsConfiguration


class S3BucketWebsiteConfigurationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_website_configuration"           # WebsiteConfiguration


class S3BucketNotificationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_notification"                    # NotificationConfiguration


class S3BucketAccelerateConfigurationAdapter(_S3BucketProjection):
    terraform_type = "aws_s3_bucket_accelerate_configuration"        # AccelerateConfiguration


class S3BucketInventoryAdapter(_S3BucketNamedProjection):
    terraform_type = "aws_s3_bucket_inventory"                       # InventoryConfigurations


class S3BucketMetricAdapter(_S3BucketNamedProjection):
    terraform_type = "aws_s3_bucket_metric"                          # MetricsConfigurations


class S3BucketAnalyticsConfigurationAdapter(_S3BucketNamedProjection):
    terraform_type = "aws_s3_bucket_analytics_configuration"         # AnalyticsConfigurations


class S3BucketIntelligentTieringConfigurationAdapter(_S3BucketNamedProjection):
    terraform_type = "aws_s3_bucket_intelligent_tiering_configuration"  # IntelligentTieringConfigurations
