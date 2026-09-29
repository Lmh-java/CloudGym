"""AWS extractor capability adapters and their shared registry.

Each supported Terraform resource type has its own module.  This package keeps
the original import surface stable for Step 1, Step 2, and snapshot callers.
"""

from .base import CapabilityAdapter
from .apigateway import (
    ApiDeploymentAdapter,
    ApiIntegrationAdapter,
    ApiMethodAdapter,
    ApiResourceAdapter,
    ApiStageAdapter,
    RestApiAdapter,
)
from .autoscaling import (
    AutoScalingAttachmentAdapter,
    AutoScalingGroupAdapter,
    LaunchConfigurationAdapter,
    LaunchTemplateAdapter,
    ScalingPolicyAdapter,
)
from .awscc_iam_role import AwsccIamRoleAdapter
from .backup import BackupPlanAdapter, BackupSelectionAdapter, BackupVaultAdapter
from .cloudwatch_metric_alarm import CloudWatchMetricAlarmAdapter
from .codebuild_project import CodeBuildProjectAdapter
from .dynamodb_table import DynamoDbTableAdapter
from .ec2_instance import InstanceAdapter, KeyPairAdapter
from .elastic_beanstalk import ElasticBeanstalkApplicationAdapter, ElasticBeanstalkEnvironmentAdapter
from .elbv2 import (
    ListenerAdapter,
    ListenerRuleAdapter,
    LoadBalancerAdapter,
    TargetGroupAdapter,
    TargetGroupAttachmentAdapter,
)
from .events_rule import EventsRuleAdapter, EventsTargetAdapter
from .firehose import FirehoseDeliveryStreamAdapter
from .glacier import GlacierVaultAdapter
from .dynamodb_item import DynamoDbTableItemAdapter
from .efs import EfsFileSystemAdapter, EfsFileSystemPolicyAdapter, EfsMountTargetAdapter
from .eip import EipAdapter
from .kinesisanalytics import KinesisAnalyticsV2ApplicationAdapter
from .lambda_extras import LambdaAliasAdapter, LambdaEventSourceMappingAdapter
from .lex import LexV2BotAdapter
from .lightsail import LightsailDiskAdapter, LightsailDiskAttachmentAdapter, LightsailInstanceAdapter
from .vpc_peering import VpcPeeringConnectionAdapter
from .network_acl import DefaultNetworkAclAdapter, NetworkAclAdapter
from .placement_group import PlacementGroupAdapter
from .sqs import SqsQueueAdapter
from .iam_instance_profile import IamInstanceProfileAdapter
from .iam_policy import IamPolicyAdapter
from .iam_role import IamRoleAdapter
from .iam_role_policy import IamRolePolicyAdapter
from .iam_role_policy_attachment import IamRolePolicyAttachmentAdapter
from .lambda_function import LambdaFunctionAdapter
from .lambda_permission import LambdaPermissionAdapter
from .logs import LogGroupAdapter, LogResourcePolicyAdapter
from .rds import (
    DbInstanceAdapter,
    DbOptionGroupAdapter,
    DbParameterGroupAdapter,
    DbSnapshotAdapter,
    DbSubnetGroupAdapter,
)
from .registry import CAPABILITY_REGISTRY, adapter_for, case_type_manifest
from .routing import (
    InternetGatewayAdapter,
    RouteAdapter,
    RouteTableAdapter,
    RouteTableAssociationAdapter,
)
from .route53 import HealthCheckAdapter, HostedZoneAdapter, QueryLogAdapter, RecordSetAdapter
from .s3_bucket import S3BucketAdapter
from .s3_bucket_policy import S3BucketPolicyAdapter
from .s3_bucket_projections import (
    S3BucketAccelerateConfigurationAdapter,
    S3BucketAnalyticsConfigurationAdapter,
    S3BucketCorsConfigurationAdapter,
    S3BucketIntelligentTieringConfigurationAdapter,
    S3BucketInventoryAdapter,
    S3BucketLifecycleConfigurationAdapter,
    S3BucketLoggingAdapter,
    S3BucketMetricAdapter,
    S3BucketNotificationAdapter,
    S3BucketObjectLockConfigurationAdapter,
    S3BucketOwnershipControlsAdapter,
    S3BucketPublicAccessBlockAdapter,
    S3BucketServerSideEncryptionConfigurationAdapter,
    S3BucketVersioningAdapter,
    S3BucketWebsiteConfigurationAdapter,
)
from .security_group import (
    SecurityGroupAdapter,
    SecurityGroupEgressRuleAdapter,
    SecurityGroupIngressRuleAdapter,
    SecurityGroupRuleAdapter,
)
from .sns_topic import SnsTopicAdapter
from .subnet import SubnetAdapter
from .vpc import VpcAdapter
from .vpc_dhcp import DhcpOptionsAdapter, DhcpOptionsAssociationAdapter

__all__ = [
    "CAPABILITY_REGISTRY",
    "ApiDeploymentAdapter",
    "ApiIntegrationAdapter",
    "ApiMethodAdapter",
    "ApiResourceAdapter",
    "ApiStageAdapter",
    "AutoScalingAttachmentAdapter",
    "AutoScalingGroupAdapter",
    "AwsccIamRoleAdapter",
    "DbOptionGroupAdapter",
    "DhcpOptionsAdapter",
    "DhcpOptionsAssociationAdapter",
    "FirehoseDeliveryStreamAdapter",
    "GlacierVaultAdapter",
    "NetworkAclAdapter",
    "DefaultNetworkAclAdapter",
    "PlacementGroupAdapter",
    "SqsQueueAdapter",
    "DynamoDbTableItemAdapter",
    "EfsFileSystemAdapter",
    "EfsFileSystemPolicyAdapter",
    "EfsMountTargetAdapter",
    "EipAdapter",
    "KinesisAnalyticsV2ApplicationAdapter",
    "LambdaAliasAdapter",
    "LambdaEventSourceMappingAdapter",
    "LexV2BotAdapter",
    "LightsailDiskAdapter",
    "LightsailDiskAttachmentAdapter",
    "LightsailInstanceAdapter",
    "VpcPeeringConnectionAdapter",
    "DbSnapshotAdapter",
    "LaunchConfigurationAdapter",
    "LaunchTemplateAdapter",
    "RestApiAdapter",
    "ScalingPolicyAdapter",
    "CapabilityAdapter",
    "CloudWatchMetricAlarmAdapter",
    "CodeBuildProjectAdapter",
    "DynamoDbTableAdapter",
    "EventsRuleAdapter",
    "EventsTargetAdapter",
    "IamPolicyAdapter",
    "IamRoleAdapter",
    "IamRolePolicyAttachmentAdapter",
    "LambdaFunctionAdapter",
    "LambdaPermissionAdapter",
    "S3BucketAdapter",
    "InternetGatewayAdapter",
    "RouteAdapter",
    "RouteTableAdapter",
    "RouteTableAssociationAdapter",
    "S3BucketLifecycleConfigurationAdapter",
    "S3BucketObjectLockConfigurationAdapter",
    "S3BucketPublicAccessBlockAdapter",
    "SecurityGroupAdapter",
    "SnsTopicAdapter",
    "SubnetAdapter",
    "VpcAdapter",
    "DbInstanceAdapter",
    "DbParameterGroupAdapter",
    "DbSubnetGroupAdapter",
    "ElasticBeanstalkApplicationAdapter",
    "ElasticBeanstalkEnvironmentAdapter",
    "ListenerAdapter",
    "ListenerRuleAdapter",
    "LoadBalancerAdapter",
    "TargetGroupAdapter",
    "TargetGroupAttachmentAdapter",
    "BackupPlanAdapter",
    "BackupSelectionAdapter",
    "BackupVaultAdapter",
    "HealthCheckAdapter",
    "HostedZoneAdapter",
    "IamInstanceProfileAdapter",
    "IamRolePolicyAdapter",
    "InstanceAdapter",
    "KeyPairAdapter",
    "LogGroupAdapter",
    "LogResourcePolicyAdapter",
    "QueryLogAdapter",
    "RecordSetAdapter",
    "S3BucketAccelerateConfigurationAdapter",
    "S3BucketAnalyticsConfigurationAdapter",
    "S3BucketCorsConfigurationAdapter",
    "S3BucketIntelligentTieringConfigurationAdapter",
    "S3BucketInventoryAdapter",
    "S3BucketLoggingAdapter",
    "S3BucketMetricAdapter",
    "S3BucketNotificationAdapter",
    "S3BucketOwnershipControlsAdapter",
    "S3BucketPolicyAdapter",
    "S3BucketServerSideEncryptionConfigurationAdapter",
    "S3BucketVersioningAdapter",
    "S3BucketWebsiteConfigurationAdapter",
    "SecurityGroupEgressRuleAdapter",
    "SecurityGroupIngressRuleAdapter",
    "SecurityGroupRuleAdapter",
    "adapter_for",
    "case_type_manifest",
]
