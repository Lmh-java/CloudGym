"""Deterministic eligibility of a Terraform configuration for the sandbox.

Shared by the IaC-Eval registry (``scripts/iac_eval_db.py``, at build time)
and the case validator (``scripts/validate_case.py``, on ``initial.tf`` /
``expected.tf``). A configuration is eligible when it declares no resource
type that is billed hourly / per instance, none from a service the sandbox
SCP denies, none the extractor cannot observe, at most one provider block
(one region), and stays under the size cap.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from harness.extractor.aws.capabilities import CAPABILITY_REGISTRY

# Resources whose running cost is material for a benchmark trial (minutes per run,
# many trials). Small EC2 instances, EBS volumes and EIPs are cents per run and are
# deliberately *not* listed; managed databases, load balancers, NAT gateways,
# clusters and search/cache domains are.
# Opened 2026-09-08 (SCP `OnlyCheapDatabaseClasses` / `NoMultiAzDatabases` cap RDS at
# db.t3/t4g micro+small single-AZ; ELBv2 and Beanstalk environments cost cents per run):
# aws_db_instance, aws_lb / aws_alb, aws_elastic_beanstalk_environment are no longer billable
# blockers. 2026-09-22: aws_kinesis_firehose_delivery_stream left too (billed per GB ingested;
# an idle stream costs nothing). 2026-09-23: aws_efs_file_system (billed per GB stored), aws_kinesisanalyticsv2_application
# (per KPU-hour only while RUNNING), aws_lexv2models_bot (per request) and aws_lightsail_instance (a nano bundle is
# ~$0.005/h) left too, for the EC diversity batch; they still need their services in the SCP. Classic ELB (aws_elb) stays out: it has no Cloud Control type to capture.
BILLABLE_TYPES = frozenset({
    "aws_rds_cluster", "aws_rds_cluster_instance", "aws_db_proxy",
    "aws_docdb_cluster", "aws_docdb_cluster_instance", "aws_neptune_cluster", "aws_neptune_cluster_instance",
    "aws_eks_cluster", "aws_eks_node_group", "aws_eks_fargate_profile", "aws_ecs_service", "aws_ecs_cluster",
    "aws_nat_gateway", "aws_elasticache_cluster", "aws_elasticache_replication_group",
    "aws_elasticache_serverless_cache", "aws_memorydb_cluster",
    "aws_redshift_cluster", "aws_redshiftserverless_workgroup", "aws_msk_cluster", "aws_msk_serverless_cluster",
    "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_opensearchserverless_collection",
    "aws_directory_service_directory", "aws_elb",
    "aws_vpn_connection", "aws_vpn_gateway", "aws_ec2_client_vpn_endpoint", "aws_ec2_transit_gateway",
    "aws_dx_connection", "aws_fsx_lustre_file_system", "aws_fsx_windows_file_system", "aws_fsx_ontap_file_system",
    "aws_sagemaker_endpoint", "aws_sagemaker_notebook_instance", "aws_sagemaker_domain",
    "aws_emr_cluster", "aws_emrserverless_application", "aws_glue_job", "aws_glue_crawler", "aws_glue_dev_endpoint",
    "aws_kinesis_stream",
    "aws_mq_broker", "aws_vpc_endpoint", "aws_secretsmanager_secret_rotation",
    "aws_apprunner_service",
    "aws_workspaces_workspace", "aws_appstream_fleet", "aws_kendra_index", "aws_lex_bot",
    "aws_cloudhsm_v2_cluster", "aws_globalaccelerator_accelerator", "aws_route53_resolver_endpoint",
    "aws_networkfirewall_firewall", "aws_gamelift_fleet", "aws_batch_compute_environment",
})

# The sandbox SCP (infra/aws/sandbox-scp.json, applied 2026-09-01, verified by live probes)
# allowlists whole services — ec2, s3, lambda, events, codebuild, dynamodb, sqs, states,
# route53, backup, sns, cloudwatch, logs — so the denial surface here is only its guardrail
# statements plus Cloud Control writes (cloudformation is Get*/List* in the allowlist, which
# keeps the awscc_* provider unusable wholesale).
SCP_DENIED_PREFIXES = (
    "awscc_",               # Cloud Control CreateResource outside the allowlist
    "aws_ec2_fleet",        # CostAndDangerGuardrails: ec2:CreateFleet
    "aws_spot_",            # CostAndDangerGuardrails: ec2:RequestSpot*
    "aws_ec2_host",         # CostAndDangerGuardrails: ec2:AllocateHosts
    "aws_ec2_capacity_",    # CostAndDangerGuardrails: ec2:*CapacityReservation*
    "aws_route53domains_",  # CostAndDangerGuardrails: route53domains:*
    # aws_backup_ left 2026-09-23: the SCP now grants the narrow kms actions Backup's vault needs
    # (DescribeKey, List*, CreateGrant, RetireGrant, GenerateDataKey*, Decrypt, Encrypt).
    # Not an SCP rule but the same effect: accounts created after mid-2024 cannot call
    # CreateLaunchConfiguration at all (UnsupportedOperation, smoke 2026-09-22). References
    # must use aws_launch_template instead.
    "aws_launch_configuration",
    # Likewise: Glacier's CreateVault returns NoLongerSupportedException for new accounts
    # (smoke 2026-09-22); the S3 Glacier storage classes replace it.
    "aws_glacier_vault",
)

# Irreversible, slow-to-delete, or account-wide state: never in a case.
DANGEROUS_TYPES = frozenset({
    "aws_kms_key", "aws_kms_external_key", "aws_kms_replica_key",
    "aws_glacier_vault_lock", "aws_backup_vault_lock_configuration",
    "aws_acmpca_certificate_authority", "aws_route53domains_registered_domain",
    "aws_cloudfront_distribution", "aws_cloudfront_origin_access_control",
    "aws_cloudhsm_v2_cluster", "aws_cloudhsm_v2_hsm",
    "aws_s3_account_public_access_block", "aws_ebs_encryption_by_default",
    "aws_iam_account_password_policy", "aws_iam_account_alias", "aws_default_vpc",
    "aws_cloudtrail", "aws_config_configuration_recorder", "aws_guardduty_detector",
    "aws_securityhub_account", "aws_macie2_account", "aws_inspector2_enabler",
    "aws_organizations_account", "aws_organizations_policy", "aws_organizations_organization",
})

MAX_REFERENCE_CHARS = 6000

_RESOURCE_DECL = re.compile(r'^\s*resource\s+"([^"]+)"', re.MULTILINE)
_DATA_DECL = re.compile(r'^\s*data\s+"([^"]+)"', re.MULTILINE)
_PROVIDER_DECL = re.compile(r'^\s*provider\s+"', re.MULTILINE)


def resource_types(hcl: str) -> list[str]:
    """Managed resource types declared in ``hcl`` (data sources excluded), sorted."""
    return sorted(set(_RESOURCE_DECL.findall(hcl)))


def data_source_types(hcl: str) -> list[str]:
    return sorted(set(_DATA_DECL.findall(hcl)))


def provider_block_count(hcl: str) -> int:
    return len(_PROVIDER_DECL.findall(hcl))


@dataclass
class Eligibility:
    eligible: bool
    blockers: list[str] = field(default_factory=list)   # machine-readable "kind:detail"
    resource_types: list[str] = field(default_factory=list)
    unmapped_types: list[str] = field(default_factory=list)

    @property
    def note(self) -> str:
        return "; ".join(self.blockers) if self.blockers else "eligible"


def assess(hcl: str, *, check_extractor: bool = True, check_size: bool = True) -> Eligibility:
    """Assess one Terraform configuration text."""
    types = resource_types(hcl)
    blockers: list[str] = []
    billable = sorted(t for t in types if t in BILLABLE_TYPES)
    if billable:
        blockers.append("billable:" + ",".join(billable))
    denied = sorted(t for t in types if t.startswith(SCP_DENIED_PREFIXES))
    if denied:
        blockers.append("scp-denied:" + ",".join(denied))
    # Billable types are reported once, as billable; an adapter would not make them usable.
    unmapped = sorted(t for t in types if t not in CAPABILITY_REGISTRY and t not in BILLABLE_TYPES)
    if check_extractor and unmapped:
        blockers.append("no-extractor:" + ",".join(unmapped))
    providers = provider_block_count(hcl)
    if providers > 1:
        blockers.append(f"multi-provider:{providers}")
    if check_size and len(hcl) > MAX_REFERENCE_CHARS:
        blockers.append(f"too-long:{len(hcl)}")
    return Eligibility(eligible=not blockers, blockers=blockers, resource_types=types, unmapped_types=unmapped)
