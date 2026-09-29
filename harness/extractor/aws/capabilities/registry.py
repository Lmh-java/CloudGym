"""Shared registry and legacy case-manifest lookup."""

from __future__ import annotations

import re
from pathlib import Path

from ...errors import UnmappedResourceType
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
from .base import CapabilityAdapter
from .cloudwatch_metric_alarm import CloudWatchMetricAlarmAdapter
from .codebuild_project import CodeBuildProjectAdapter
from .dynamodb_table import DynamoDbTableAdapter
from .dynamodb_item import DynamoDbTableItemAdapter
from .ec2_instance import InstanceAdapter, KeyPairAdapter
from .efs import EfsFileSystemAdapter, EfsFileSystemPolicyAdapter, EfsMountTargetAdapter
from .eip import EipAdapter
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
from .iam_instance_profile import IamInstanceProfileAdapter
from .iam_policy import IamPolicyAdapter
from .iam_role import IamRoleAdapter
from .iam_role_policy import IamRolePolicyAdapter
from .iam_role_policy_attachment import IamRolePolicyAttachmentAdapter
from .kinesisanalytics import KinesisAnalyticsV2ApplicationAdapter
from .lambda_function import LambdaFunctionAdapter
from .lambda_extras import LambdaAliasAdapter, LambdaEventSourceMappingAdapter
from .lambda_permission import LambdaPermissionAdapter
from .lex import LexV2BotAdapter
from .lightsail import LightsailDiskAdapter, LightsailDiskAttachmentAdapter, LightsailInstanceAdapter
from .logs import LogGroupAdapter, LogResourcePolicyAdapter
from .network_acl import DefaultNetworkAclAdapter, NetworkAclAdapter
from .placement_group import PlacementGroupAdapter
from .rds import (
    DbInstanceAdapter,
    DbOptionGroupAdapter,
    DbParameterGroupAdapter,
    DbSnapshotAdapter,
    DbSubnetGroupAdapter,
)
from .route53 import HealthCheckAdapter, HostedZoneAdapter, QueryLogAdapter, RecordSetAdapter
from .routing import (
    InternetGatewayAdapter,
    RouteAdapter,
    RouteTableAdapter,
    RouteTableAssociationAdapter,
)
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
from .sqs import SqsQueueAdapter
from .subnet import SubnetAdapter
from .vpc import VpcAdapter
from .vpc_dhcp import DhcpOptionsAdapter, DhcpOptionsAssociationAdapter
from .vpc_peering import VpcPeeringConnectionAdapter

_RESOURCE_DECL = re.compile(
    r'^\s*resource\s+"([^"]+)"', re.MULTILINE)

CAPABILITY_REGISTRY: dict[str, CapabilityAdapter] = {
    adapter.terraform_type: adapter
    for adapter in (
        VpcAdapter(),
        SubnetAdapter(),
        SecurityGroupAdapter(),
        S3BucketAdapter(),
        AwsccIamRoleAdapter(),
        SnsTopicAdapter(),
        IamRoleAdapter(),
        CloudWatchMetricAlarmAdapter(),
        S3BucketLifecycleConfigurationAdapter(),
        S3BucketPublicAccessBlockAdapter(),
        S3BucketObjectLockConfigurationAdapter(),
        LambdaFunctionAdapter(),
        LambdaPermissionAdapter(),
        EventsRuleAdapter(),
        EventsTargetAdapter(),
        IamRolePolicyAttachmentAdapter(),
        IamPolicyAdapter(),
        CodeBuildProjectAdapter(),
        DynamoDbTableAdapter(),
        InternetGatewayAdapter(),
        RouteTableAdapter(),
        RouteTableAssociationAdapter(),
        RouteAdapter(),
        # 2026-09-08 batch: S3 projections, SG rule projections, inline role policies,
        # Logs, bucket policies, Backup, EC2 instance / key pair / instance profile, Route 53.
        S3BucketVersioningAdapter(),
        S3BucketServerSideEncryptionConfigurationAdapter(),
        S3BucketOwnershipControlsAdapter(),
        S3BucketLoggingAdapter(),
        S3BucketCorsConfigurationAdapter(),
        S3BucketWebsiteConfigurationAdapter(),
        S3BucketNotificationAdapter(),
        S3BucketAccelerateConfigurationAdapter(),
        S3BucketInventoryAdapter(),
        S3BucketMetricAdapter(),
        S3BucketAnalyticsConfigurationAdapter(),
        S3BucketIntelligentTieringConfigurationAdapter(),
        S3BucketPolicyAdapter(),
        SecurityGroupIngressRuleAdapter(),
        SecurityGroupEgressRuleAdapter(),
        SecurityGroupRuleAdapter(),
        IamRolePolicyAdapter(),
        IamInstanceProfileAdapter(),
        LogGroupAdapter(),
        LogResourcePolicyAdapter(),
        BackupVaultAdapter(),
        BackupPlanAdapter(),
        BackupSelectionAdapter(),
        InstanceAdapter(),
        KeyPairAdapter(),
        HostedZoneAdapter(),
        QueryLogAdapter(),
        RecordSetAdapter(),
        HealthCheckAdapter(),
        # 2026-09-08, opened with the SCP (rds / elasticloadbalancing / elasticbeanstalk).
        DbInstanceAdapter(),
        DbSubnetGroupAdapter(),
        DbParameterGroupAdapter(),
        LoadBalancerAdapter(),
        TargetGroupAdapter(),
        TargetGroupAttachmentAdapter(),
        ListenerAdapter(),
        ListenerRuleAdapter(),
        ElasticBeanstalkApplicationAdapter(),
        ElasticBeanstalkEnvironmentAdapter(),
        # 2026-09-22, EC seed pool: Auto Scaling (allowlisted already), RDS option group and
        # manual snapshot.
        LaunchConfigurationAdapter(),
        LaunchTemplateAdapter(),
        AutoScalingGroupAdapter(),
        AutoScalingAttachmentAdapter(),
        ScalingPolicyAdapter(),
        DbOptionGroupAdapter(),
        DbSnapshotAdapter(),
        # 2026-09-22, coverage batch: DHCP options, API Gateway REST, Firehose, Glacier.
        DhcpOptionsAdapter(),
        DhcpOptionsAssociationAdapter(),
        RestApiAdapter(),
        ApiResourceAdapter(),
        ApiMethodAdapter(),
        ApiIntegrationAdapter(),
        ApiDeploymentAdapter(),
        ApiStageAdapter(),
        FirehoseDeliveryStreamAdapter(),
        GlacierVaultAdapter(),
        # 2026-09-23: SQS queue, placement group, network ACLs (rows 131/192/237/455-457).
        SqsQueueAdapter(),
        PlacementGroupAdapter(),
        NetworkAclAdapter(),
        DefaultNetworkAclAdapter(),
        # 2026-09-23, EC diversity batch: event-source mapping, alias, table item, Elastic IP,
        # VPC peering, EFS, Lightsail, Managed Flink, Lex V2.
        LambdaEventSourceMappingAdapter(),
        LambdaAliasAdapter(),
        DynamoDbTableItemAdapter(),
        EipAdapter(),
        VpcPeeringConnectionAdapter(),
        EfsFileSystemAdapter(),
        EfsFileSystemPolicyAdapter(),
        EfsMountTargetAdapter(),
        LightsailInstanceAdapter(),
        LightsailDiskAdapter(),
        LightsailDiskAttachmentAdapter(),
        KinesisAnalyticsV2ApplicationAdapter(),
        LexV2BotAdapter(),
    )
}


def adapter_for(terraform_type: str) -> CapabilityAdapter:
    try:
        return CAPABILITY_REGISTRY[terraform_type]
    except KeyError:
        raise UnmappedResourceType(
            f"no capability adapter for {terraform_type!r} "
            f"(add one under harness/extractor/aws/capabilities/)") from None


def case_type_manifest(case_dir: Path) -> list[str]:
    """Cloud Control names for resource types declared by a legacy case."""
    tf_files = (sorted(case_dir.glob("initial/*.tf"))
                + sorted(case_dir.glob("expected/*.tf")))
    tf_types = {
        match.group(1)
        for terraform_file in tf_files
        for match in _RESOURCE_DECL.finditer(terraform_file.read_text())
    }
    unmapped = sorted(tf_types - CAPABILITY_REGISTRY.keys())
    if unmapped:
        raise UnmappedResourceType(
            f"no capability adapter for: {', '.join(unmapped)} "
            f"(add one under harness/extractor/aws/capabilities/)"
        )
    return sorted({
        CAPABILITY_REGISTRY[terraform_type].cloudcontrol_type
        for terraform_type in tf_types
    })
