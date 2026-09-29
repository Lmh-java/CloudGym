"""Turn a case directory (or a bare seed) into runtime inputs and lifecycle hooks.

A *case directory* is self-contained: its own ``initial.tf`` is what gets
deployed, ``expected.tf`` is the clean witness of the task (used to widen the
observed resource types), and ``agent/task.json`` carries the utterance. The
``seed_id`` it records is provenance — the seed under ``seeds/aws/<seed-id>/``
is where the Terraform was copied from — and is only consulted when the case
has no ``initial.tf`` of its own (or when running a bare seed, unscored).

    <case-dir>/
      initial.tf
      expected.tf
      agent/task.json
      agent/resolution_prompt.txt
      evaluator/oracle.rego
      evaluator/distractors/<distractor-id>/distractor.py
      evaluator/invariants/<invariant-id>/invariant.py

Invariants are ``@invariant`` predicates checked on every observation; their
violation history reaches the oracle as ``input.invariants`` so a transient
safety violation can fail a run whose final snapshot looks healthy.

The hooks built here run Terraform for deploy/destroy and use region-wide
Cloud Control capture for every observation, so resources the agent creates
outside Terraform are visible to triggers, the oracle, and the leak check.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..extractor.aws import capture_snapshot, parse_envelope
from ..prompts import load_prompt
from ..extractor.aws.capabilities import CAPABILITY_REGISTRY
from ..extractor.shape import shape_snapshot
from ..terraform.workspace import Workspace
from .config import declared_invariant, declared_triggers_for, sha256_file
from .coordinator import LifecycleHooks
from .distractors import DistractorDefinition
from .invariants import InvariantDefinition, InvariantSpec
from .matcher import TriggerSpec
from ..netcheck import is_transient_network_error
from .vpc_teardown import clear_vpc_dependencies
from harness.awareness import POLICY_WITHHELD

# A failed delete is retried: ELB network-interface release lags the load balancer's
# deletion, and the security groups and subnets that held them refuse to go until then.
_EXTRA_DELETE_ATTEMPTS = 3
_EXTRA_DELETE_BACKOFF_S = 20
_VPC_DRAIN_DEADLINE_S = 300
_VPC_DRAIN_INTERVAL_S = 10

# Children before parents when deleting agent-created extras.
# Waits between destroy attempts when the failure is the network, not the account.
_DESTROY_NETWORK_BACKOFF_S = (15, 45, 120)

DELETE_ORDER = {
    "AWS::Lambda::Permission": 5,
    "AWS::ElasticLoadBalancingV2::ListenerRule": 3,
    "AWS::ElasticLoadBalancingV2::Listener": 4,
    "AWS::ElasticBeanstalk::Environment": 5,
    "AWS::RDS::DBInstance": 8,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": 8,
    "AWS::ElasticLoadBalancingV2::TargetGroup": 12,
    "AWS::RDS::DBSubnetGroup": 20,
    "AWS::RDS::DBParameterGroup": 20,
    "AWS::ElasticBeanstalk::Application": 20,
    "AWS::AutoScaling::ScalingPolicy": 3,
    "AWS::RDS::DBSnapshot": 5,
    "AWS::AutoScaling::AutoScalingGroup": 6,
    "AWS::AutoScaling::LaunchConfiguration": 12,
    "AWS::EC2::LaunchTemplate": 12,
    "AWS::RDS::OptionGroup": 20,
    "AWS::ApiGateway::Method": 3,
    "AWS::ApiGateway::Stage": 3,
    "AWS::ApiGateway::Resource": 4,
    "AWS::ApiGateway::Deployment": 4,
    "AWS::ApiGateway::RestApi": 10,
    "AWS::EC2::VPCDHCPOptionsAssociation": 5,
    "AWS::EC2::DHCPOptions": 95,          # after the VPCs (90) that hold it
    "AWS::KinesisFirehose::DeliveryStream": 8,
    "AWS::Glacier::Vault": 20,
    "AWS::SQS::Queue": 20,
    "AWS::EC2::PlacementGroup": 20,       # after the instances (5) that sit in it
    "AWS::EC2::NetworkAcl": 12,           # after the subnets (10), before the VPC (90)
    "AWS::Lambda::EventSourceMapping": 4,  # before the function (20) and its source table (20)
    "AWS::Lambda::Alias": 4,
    "AWS::DynamoDB::TableItem": 10,       # before the table (20)
    "AWS::EC2::EIP": 30,                  # after instances (5) and load balancers (8) release it
    "AWS::EC2::VPCPeeringConnection": 50, # before either VPC (90)
    "AWS::EFS::MountTarget": 8,           # before the file system (20) and the subnet (10)
    "AWS::EFS::FileSystem": 20,
    "AWS::Lightsail::Instance": 5,        # deleting the instance detaches its disks
    "AWS::Lightsail::Disk": 10,
    "AWS::KinesisAnalyticsV2::Application": 10,
    "AWS::Lex::Bot": 10,
    "AWS::Route53::RecordSet": 5,
    "AWS::Route53::QueryLoggingConfig": 4,
    "AWS::Backup::BackupSelection": 5,
    "AWS::S3::BucketPolicy": 5,
    "AWS::EC2::Instance": 5,
    "AWS::EC2::KeyPair": 10,
    "AWS::Backup::BackupPlan": 10,
    "AWS::Route53::HealthCheck": 10,
    "AWS::Backup::BackupVault": 20,
    "AWS::Route53::HostedZone": 20,
    "AWS::Logs::LogGroup": 20,
    "AWS::Logs::ResourcePolicy": 20,
    "AWS::IAM::InstanceProfile": 25,
    "AWS::EC2::Route": 5,
    "AWS::EC2::SubnetRouteTableAssociation": 5,
    "AWS::EC2::Subnet": 10,
    "AWS::EC2::RouteTable": 15,
    "AWS::EC2::InternetGateway": 15,
    "AWS::EC2::SecurityGroup": 10,
    "AWS::CloudWatch::Alarm": 10,
    "AWS::CodeBuild::Project": 20,
    "AWS::DynamoDB::Table": 20,
    "AWS::IAM::ManagedPolicy": 25,
    "AWS::Events::Rule": 10,
    "AWS::SNS::Topic": 20,
    "AWS::S3::Bucket": 20,
    "AWS::Lambda::Function": 20,
    "AWS::IAM::Role": 30,
    "AWS::EC2::VPC": 90,
}

_RESOURCE_DECL = re.compile(r'^\s*resource\s+"([^"]+)"', re.MULTILINE)


class CaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class CaseSpec:
    seed_id: str
    seed_dir: Path
    initial_tf: tuple[Path, ...]
    utterance: str
    terraform_types: tuple[str, ...]
    cloudcontrol_types: tuple[str, ...]
    case_dir: Path | None = None
    resolution_prompt: str | None = None
    oracle_path: Path | None = None
    distractor_sources: Mapping[str, Path] = field(default_factory=dict)
    invariant_sources: Mapping[str, Path] = field(default_factory=dict)

    def input_hashes(self) -> dict[str, str]:
        hashes = {f"initial/{path.name}": sha256_file(path) for path in self.initial_tf}
        if self.oracle_path:
            hashes["oracle.rego"] = sha256_file(self.oracle_path)
        for distractor_id, source in self.distractor_sources.items():
            hashes[f"distractor/{distractor_id}"] = sha256_file(source)
        for invariant_id, source in self.invariant_sources.items():
            hashes[f"invariant/{invariant_id}"] = sha256_file(source)
        # Files the task hands the agent (copied into its workspace before launch).
        files_dir = self.case_dir / "agent" / "files" if self.case_dir else None
        if files_dir and files_dir.is_dir():
            for path in sorted(files_dir.rglob("*")):
                if path.is_file():
                    hashes[f"files/{path.relative_to(files_dir).as_posix()}"] = sha256_file(path)
        return hashes


def _terraform_types(tf_files: tuple[Path, ...]) -> tuple[str, ...]:
    return tuple(sorted({
        match.group(1)
        for path in tf_files
        for match in _RESOURCE_DECL.finditer(path.read_text())
    }))


def load_case(seed_id: str, seeds_dir: Path, case_dir: Path | None = None) -> CaseSpec:
    seed_dir = seeds_dir / seed_id
    if case_dir is not None and not case_dir.is_dir():
        raise CaseError(f"case directory does not exist: {case_dir}")
    if case_dir is not None and (case_dir / "initial.tf").is_file():
        # Self-contained case: its own Terraform and utterance; the seed is provenance.
        initial_tf = (case_dir / "initial.tf",)
        expected_file = case_dir / "expected.tf"
        expected_tf = (expected_file,) if expected_file.is_file() else ()
        task_file = case_dir / "agent" / "task.json"
        try:
            source = json.loads(task_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise CaseError(f"{task_file}: {exc}") from None
        if "utterance" not in source:
            raise CaseError(f"{task_file} has no utterance")
    else:
        if not seed_dir.is_dir():
            raise CaseError(f"unknown seed {seed_id!r} under {seeds_dir}")
        source = json.loads((seed_dir / "source.json").read_text())
        initial_tf = tuple(sorted((seed_dir / "initial").glob("*.tf")))
        if not initial_tf:
            raise CaseError(f"seed {seed_id} has no initial/*.tf")
        expected_tf = tuple(sorted((seed_dir / "expected").glob("*.tf")))
    # Types the agent is expected to touch: everything the initial and expected
    # configurations declare, so the expected outcome is observable.
    declared = set(source.get("resource_types", [])) | set(_terraform_types(initial_tf + expected_tf))
    unmapped = sorted(declared - CAPABILITY_REGISTRY.keys())
    if unmapped:
        raise CaseError(f"no extractor capability for: {', '.join(unmapped)}")
    terraform_types = tuple(sorted(declared))
    cloudcontrol_types = tuple(sorted({CAPABILITY_REGISTRY[t].cloudcontrol_type for t in terraform_types}))

    resolution_prompt = oracle_path = None
    distractors: dict[str, Path] = {}
    invariants: dict[str, Path] = {}
    if case_dir is not None:
        prompt_file = case_dir / "agent" / "resolution_prompt.txt"
        if prompt_file.is_file():
            resolution_prompt = prompt_file.read_text().strip() or None
        oracle_file = case_dir / "evaluator" / "oracle.rego"
        if oracle_file.is_file():
            oracle_path = oracle_file
        for module in sorted((case_dir / "evaluator" / "distractors").glob("*/distractor.py")):
            distractors[module.parent.name] = module
        for module in sorted((case_dir / "evaluator" / "invariants").glob("*/invariant.py")):
            invariants[module.parent.name] = module
    return CaseSpec(
        seed_id=seed_id,
        seed_dir=seed_dir,
        initial_tf=initial_tf,
        utterance=str(source["utterance"]).strip(),
        terraform_types=terraform_types,
        cloudcontrol_types=cloudcontrol_types,
        case_dir=case_dir,
        resolution_prompt=resolution_prompt,
        oracle_path=oracle_path,
        distractor_sources=distractors,
        invariant_sources=invariants,
    )


# How the agent is told to manage the infrastructure. ``hybrid`` is the historical prompt
# (the agent picks CLI, SDK or Terraform); the others pin one modality. Only the prompt
# changes — the tools on the agent's PATH and the proxy are the same in every arm.
MODALITIES = ("hybrid", "iac", "sdk", "cli")


def build_prompt(spec: CaseSpec, *, region: str, mcp_server_name: str = "cloudgym",
                 awareness: str = "none", modality: str = "hybrid", policy: bool = True) -> str:
    """The task prompt handed to the agent (template: ``harness/prompts/agent_task.md``).

    The prompt never says the environment is shared. With ``awareness`` other
    than ``none`` it lists the awareness tool in one flat sentence; what
    that tool reveals is decided by the MCP server, not the prompt. ``modality``
    picks the management-tooling paragraph (``harness/prompts/modality_<name>.md``).

    The ``consult`` levels are the ones that change the prompt's content rather than just
    its tool list: the resolution policy is withheld, because the whole point of those arms
    is that the agent has to ask for it. Every other level states the policy up front.
    ``consult`` and ``consult_open`` render an identical prompt — they differ only in
    whether a principal answers before its program has landed.
    """
    if modality not in MODALITIES:
        raise CaseError(f"modality must be one of {MODALITIES}, got {modality!r}")
    include_policy = policy
    policy = spec.resolution_prompt.strip() if spec.resolution_prompt else ""
    if awareness in POLICY_WITHHELD or not include_policy:
        policy = ""
    tools_prompt = {"none": "tools_finish_only", "consult": "tools_consult",
                    "consult_open": "tools_consult"}.get(awareness, "tools_with_changes")
    return load_prompt(
        "agent_task",
        region=region,
        task=spec.utterance.strip('"'),
        policy_section=f"\n## Policy\n{policy}\n" if policy else "",
        mcp_server_name=mcp_server_name,
        tools=load_prompt(tools_prompt).strip(),
        modality_section=load_prompt(f"modality_{modality}").strip(),
    )


def distractor_definitions(spec: CaseSpec, *, timeout: float = 120.0) -> dict[str, DistractorDefinition]:
    return {
        distractor_id: DistractorDefinition(
            distractor_id=distractor_id,
            source_path=source.resolve(),
            sha256=sha256_file(source),
            timeout=timeout,
        )
        for distractor_id, source in spec.distractor_sources.items()
    }


def declared_triggers(definitions: Mapping[str, DistractorDefinition]) -> tuple[TriggerSpec, ...]:
    return tuple(t for definition in definitions.values() for t in declared_triggers_for(definition))


def invariant_definitions(spec: CaseSpec) -> dict[str, InvariantDefinition]:
    return {
        invariant_id: InvariantDefinition(
            invariant_id=invariant_id,
            source_path=source.resolve(),
            sha256=sha256_file(source),
        )
        for invariant_id, source in spec.invariant_sources.items()
    }


def declared_invariants(definitions: Mapping[str, InvariantDefinition]) -> tuple[InvariantSpec, ...]:
    return tuple(declared_invariant(definition) for definition in definitions.values())


def _resource_ids(snapshot: Mapping[str, Any]) -> set[tuple[str, str]]:
    resources = snapshot.get("resources", {})
    ids: set[tuple[str, str]] = set()
    for type_name, items in resources.items():
        for identifier, properties in items.items():
            if type_name == "AWS::IAM::Role" and str(
                    (properties or {}).get("Path", "")).startswith("/aws-service-role/"):
                # AWS creates service-linked roles on a service's first use (Auto Scaling,
                # Elastic Beanstalk, ...); they are account fixtures, not something a run
                # can leak or delete, so they never count against a leak check.
                continue
            if type_name == "AWS::RDS::OptionGroup" and identifier.startswith("default:"):
                # RDS materialises ``default:<engine>-<major>`` the first time an engine's
                # option groups are touched; it cannot be deleted and is not a leak.
                continue
            ids.add((type_name, identifier))
    return ids


_ELB_INTERFACE_ATTEMPTS = 30
_ELB_INTERFACE_DELAY_S = 5


def _wait_for_elb_interfaces(session, load_balancer_arn: str) -> None:
    """Block until a deleted load balancer's network interfaces are gone.

    Its interfaces carry the description ``ELB <net|app>/<name>/<id>`` — the tail of
    the ARN — so they can be waited on by name without knowing the subnets.
    """
    _, _, suffix = load_balancer_arn.partition(":loadbalancer/")
    if not suffix:
        return
    ec2 = session.client("ec2")
    interface_filter = [{"Name": "description", "Values": [f"ELB {suffix}"]}]
    for attempt in range(_ELB_INTERFACE_ATTEMPTS):
        remaining = ec2.describe_network_interfaces(
            Filters=interface_filter)["NetworkInterfaces"]
        if not remaining:
            return
        if attempt < _ELB_INTERFACE_ATTEMPTS - 1:
            time.sleep(_ELB_INTERFACE_DELAY_S)


def _dynamodb_settled(dynamodb, name: str, *, timeout_s: float = 600.0, poll_s: float = 5.0) -> bool:
    """Block until the table and all its global secondary indexes report ACTIVE (or the
    table is gone). Returns False on timeout; the caller then attempts the delete anyway."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = dynamodb.describe_table(TableName=name)["Table"]
        except Exception as exc:  # noqa: BLE001 - a missing table is "settled"
            if "ResourceNotFound" in type(exc).__name__ or "ResourceNotFound" in str(exc):
                return True
            raise
        statuses = [desc.get("TableStatus")] + [g.get("IndexStatus") for g in desc.get("GlobalSecondaryIndexes") or []]
        if all(s == "ACTIVE" for s in statuses):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_s)


def delete_resource(session, type_name: str, identifier: str) -> None:
    """Delete one resource with its native service API.

    Cloud Control's DeleteResource is denied by the sandbox SCP, so each
    supported type maps to the service call. Unsupported types raise.
    """
    region = session.region_name
    if type_name == "AWS::EC2::Subnet":
        session.client("ec2").delete_subnet(SubnetId=identifier)
    elif type_name == "AWS::Route53::QueryLoggingConfig":
        session.client("route53").delete_query_logging_config(Id=identifier)
    elif type_name == "AWS::EC2::SecurityGroup":
        ec2 = session.client("ec2")
        # A group cannot be deleted while any rule references it — its own rules or a rule in
        # a sibling group of the same VPC (an agent's LB group admitting the instance group,
        # for instance; iac-eval row 402 stranded two VPCs this way). Revoke both first.
        described = ec2.describe_security_groups(GroupIds=[identifier])["SecurityGroups"]
        vpc_id = described[0].get("VpcId") if described else None
        if described and described[0].get("GroupName") == "default":
            # A VPC's default group cannot be deleted and goes with the VPC itself;
            # attempting it only spends the retry backoff and reports a false failure.
            return
        rules = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [identifier]}]).get("SecurityGroupRules", [])
        if vpc_id:
            siblings = [g["GroupId"] for g in ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"] if g["GroupId"] != identifier]
            for start in range(0, len(siblings), 100):
                rules += [r for r in ec2.describe_security_group_rules(
                    Filters=[{"Name": "group-id", "Values": siblings[start:start + 100]}]).get("SecurityGroupRules", [])
                    if (r.get("ReferencedGroupInfo") or {}).get("GroupId") == identifier]
        for group_id in {r["GroupId"] for r in rules}:
            ingress = [r["SecurityGroupRuleId"] for r in rules if r["GroupId"] == group_id and not r["IsEgress"]]
            egress = [r["SecurityGroupRuleId"] for r in rules if r["GroupId"] == group_id and r["IsEgress"]]
            if ingress:
                ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=ingress)
            if egress:
                ec2.revoke_security_group_egress(GroupId=group_id, SecurityGroupRuleIds=egress)
        ec2.delete_security_group(GroupId=identifier)
    elif type_name == "AWS::EC2::VPC":
        session.client("ec2").delete_vpc(VpcId=identifier)
    elif type_name == "AWS::SNS::Topic":
        session.client("sns").delete_topic(TopicArn=identifier)
    elif type_name == "AWS::CloudWatch::Alarm":
        session.client("cloudwatch").delete_alarms(AlarmNames=[identifier])
    elif type_name == "AWS::S3::Bucket":
        s3 = session.resource("s3")
        bucket = s3.Bucket(identifier)
        bucket.object_versions.delete()
        bucket.objects.all().delete()
        bucket.delete()
    elif type_name == "AWS::IAM::Role":
        iam = session.client("iam")
        for policy in iam.list_attached_role_policies(RoleName=identifier)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=identifier, PolicyArn=policy["PolicyArn"])
        for name in iam.list_role_policies(RoleName=identifier)["PolicyNames"]:
            iam.delete_role_policy(RoleName=identifier, PolicyName=name)
        iam.delete_role(RoleName=identifier)
    elif type_name == "AWS::CodeBuild::Project":
        session.client("codebuild").delete_project(name=identifier)
    elif type_name == "AWS::DynamoDB::Table":
        from botocore.exceptions import ClientError

        dynamodb = session.client("dynamodb")
        # An agent asked to protect a store may set DeletionProtectionEnabled, and
        # DeleteTable then fails with a ValidationException; clear it first, the way
        # the RDS and ELBv2 branches clear their deletion protection.
        # A distractor (or the agent) may leave the table mid-change: a global secondary
        # index still CREATING/UPDATING, or the table itself UPDATING. DeleteTable is
        # refused (ResourceInUseException) until that settles, and the teardown's few
        # quick retries are not enough, so the account is left dirty with the table on
        # it. Wait for the table and every index to be ACTIVE first.
        _dynamodb_settled(dynamodb, identifier)
        try:
            dynamodb.update_table(TableName=identifier, DeletionProtectionEnabled=False)
            dynamodb.get_waiter("table_exists").wait(
                TableName=identifier, WaiterConfig={"Delay": 3, "MaxAttempts": 40})
        except ClientError:
            pass
        _dynamodb_settled(dynamodb, identifier)
        dynamodb.delete_table(TableName=identifier)
        dynamodb.get_waiter("table_not_exists").wait(
            TableName=identifier, WaiterConfig={"Delay": 3, "MaxAttempts": 60})
    elif type_name == "AWS::IAM::ManagedPolicy":
        iam = session.client("iam")
        entities = iam.list_entities_for_policy(PolicyArn=identifier)
        for role in entities.get("PolicyRoles", []):
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=identifier)
        for user in entities.get("PolicyUsers", []):
            iam.detach_user_policy(UserName=user["UserName"], PolicyArn=identifier)
        for group in entities.get("PolicyGroups", []):
            iam.detach_group_policy(GroupName=group["GroupName"], PolicyArn=identifier)
        for version in iam.list_policy_versions(PolicyArn=identifier)["Versions"]:
            if not version["IsDefaultVersion"]:
                iam.delete_policy_version(PolicyArn=identifier, VersionId=version["VersionId"])
        iam.delete_policy(PolicyArn=identifier)
    elif type_name == "AWS::Lambda::Function":
        from harness.runtime.refusals import wait_until_settled

        # A function still Pending (VPC attachment) or with an update InProgress refuses
        # deletion with ResourceConflictException; wait for both state machines.
        wait_until_settled(session, "lambda.function", identifier, timeout_s=600.0)
        session.client("lambda").delete_function(FunctionName=identifier)
    elif type_name == "AWS::Lambda::Permission":
        # Cloud Control identifier is "<FunctionName>|<StatementId>".
        function_name, statement_id = identifier.split("|", 1)
        session.client("lambda").remove_permission(FunctionName=function_name, StatementId=statement_id)
    elif type_name == "AWS::EC2::InternetGateway":
        ec2 = session.client("ec2")
        gateways = ec2.describe_internet_gateways(InternetGatewayIds=[identifier])["InternetGateways"]
        for attachment in (gateways[0].get("Attachments", []) if gateways else []):
            ec2.detach_internet_gateway(InternetGatewayId=identifier, VpcId=attachment["VpcId"])
        ec2.delete_internet_gateway(InternetGatewayId=identifier)
    elif type_name == "AWS::EC2::RouteTable":
        session.client("ec2").delete_route_table(RouteTableId=identifier)
    elif type_name == "AWS::EC2::SubnetRouteTableAssociation":
        session.client("ec2").disassociate_route_table(AssociationId=identifier)
    elif type_name == "AWS::EC2::Route":
        # Cloud Control identifier is "<RouteTableId>|<destination>". The implicit `local`
        # route cannot be deleted and vanishes with its VPC; ignore that specific refusal.
        from botocore.exceptions import ClientError

        table, destination = identifier.split("|", 1)
        ec2 = session.client("ec2")
        try:
            if ":" in destination:
                ec2.delete_route(RouteTableId=table, DestinationIpv6CidrBlock=destination)
            else:
                ec2.delete_route(RouteTableId=table, DestinationCidrBlock=destination)
        except ClientError as exc:
            message = str(exc)
            if "local" not in message and "InvalidRoute.NotFound" not in message:
                raise
    elif type_name == "AWS::Events::Rule":
        # Cloud Control identifier is the rule ARN: arn:aws:events:<region>:<acct>:rule/[<bus>/]<name>
        events = session.client("events")
        path = identifier.split(":rule/", 1)[1]
        bus, _, name = path.rpartition("/") if "/" in path else ("default", "", path)
        targets = events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]
        if targets:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=[t["Id"] for t in targets])
        events.delete_rule(Name=name, EventBusName=bus)
    elif type_name == "AWS::S3::BucketPolicy":
        session.client("s3").delete_bucket_policy(Bucket=identifier)
    elif type_name == "AWS::Logs::LogGroup":
        session.client("logs").delete_log_group(logGroupName=identifier)
    elif type_name == "AWS::Logs::ResourcePolicy":
        session.client("logs").delete_resource_policy(policyName=identifier)
    elif type_name == "AWS::IAM::InstanceProfile":
        iam = session.client("iam")
        profile = iam.get_instance_profile(InstanceProfileName=identifier)["InstanceProfile"]
        for role in profile.get("Roles", []):
            iam.remove_role_from_instance_profile(InstanceProfileName=identifier, RoleName=role["RoleName"])
        iam.delete_instance_profile(InstanceProfileName=identifier)
    elif type_name == "AWS::EC2::Instance":
        ec2 = session.client("ec2")
        ec2.terminate_instances(InstanceIds=[identifier])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[identifier], WaiterConfig={"Delay": 5, "MaxAttempts": 60})
    elif type_name == "AWS::EC2::KeyPair":
        session.client("ec2").delete_key_pair(KeyName=identifier)
    elif type_name == "AWS::Backup::BackupSelection":
        # Cloud Control identifier is "<BackupPlanId>_<SelectionId>".
        plan_id, selection_id = identifier.split("_", 1)
        session.client("backup").delete_backup_selection(BackupPlanId=plan_id, SelectionId=selection_id)
    elif type_name == "AWS::Backup::BackupPlan":
        backup = session.client("backup")
        for selection in backup.list_backup_selections(BackupPlanId=identifier).get("BackupSelectionsList", []):
            backup.delete_backup_selection(BackupPlanId=identifier, SelectionId=selection["SelectionId"])
        backup.delete_backup_plan(BackupPlanId=identifier)
    elif type_name == "AWS::Backup::BackupVault":
        backup = session.client("backup")
        for point in backup.list_recovery_points_by_backup_vault(
                BackupVaultName=identifier).get("RecoveryPoints", []):
            backup.delete_recovery_point(BackupVaultName=identifier,
                                         RecoveryPointArn=point["RecoveryPointArn"])
        backup.delete_backup_vault(BackupVaultName=identifier)
    elif type_name == "AWS::Route53::RecordSet":
        # Cloud Control identifier is "<name>|<zone id>|<type>|<set identifier>".
        name, zone_id, record_type, set_identifier = identifier.split("|", 3)
        route53 = session.client("route53")
        listed = route53.list_resource_record_sets(
            HostedZoneId=zone_id, StartRecordName=name, StartRecordType=record_type,
            **({"StartRecordIdentifier": set_identifier} if set_identifier else {}), MaxItems="1")
        for record in listed.get("ResourceRecordSets", []):
            if (record["Name"].rstrip(".").lower() == name.rstrip(".").lower()
                    and record["Type"] == record_type
                    and record.get("SetIdentifier", "") == set_identifier):
                route53.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": record}]})
    elif type_name == "AWS::Route53::HostedZone":
        route53 = session.client("route53")
        zone_name = route53.get_hosted_zone(Id=identifier)["HostedZone"]["Name"]
        changes = []
        for page in route53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=identifier):
            for record in page["ResourceRecordSets"]:
                if record["Type"] in ("NS", "SOA") and record["Name"] == zone_name:
                    continue  # the apex NS/SOA pair is deleted with the zone
                changes.append({"Action": "DELETE", "ResourceRecordSet": record})
        for start in range(0, len(changes), 100):
            route53.change_resource_record_sets(
                HostedZoneId=identifier, ChangeBatch={"Changes": changes[start:start + 100]})
        route53.delete_hosted_zone(Id=identifier)
    elif type_name == "AWS::Route53::HealthCheck":
        session.client("route53").delete_health_check(HealthCheckId=identifier)
    elif type_name == "AWS::RDS::DBInstance":
        from harness.runtime.refusals import wait_until_settled

        rds = session.client("rds")
        # An EC case leaves the instance modifying / backing-up; both refuse the modify and
        # the delete below with InvalidDBInstanceState, so wait for `available` first.
        wait_until_settled(session, "rds.db-instance", identifier, timeout_s=1200.0, poll_s=15.0)
        rds.modify_db_instance(DBInstanceIdentifier=identifier, DeletionProtection=False,
                               ApplyImmediately=True)
        wait_until_settled(session, "rds.db-instance", identifier, timeout_s=1200.0, poll_s=15.0)
        rds.delete_db_instance(DBInstanceIdentifier=identifier, SkipFinalSnapshot=True,
                               DeleteAutomatedBackups=True)
        rds.get_waiter("db_instance_deleted").wait(
            DBInstanceIdentifier=identifier, WaiterConfig={"Delay": 15, "MaxAttempts": 80})
    elif type_name == "AWS::RDS::DBSubnetGroup":
        session.client("rds").delete_db_subnet_group(DBSubnetGroupName=identifier)
    elif type_name == "AWS::RDS::DBParameterGroup":
        session.client("rds").delete_db_parameter_group(DBParameterGroupName=identifier)
    elif type_name == "AWS::ElasticLoadBalancingV2::ListenerRule":
        session.client("elbv2").delete_rule(RuleArn=identifier)
    elif type_name == "AWS::ElasticLoadBalancingV2::Listener":
        session.client("elbv2").delete_listener(ListenerArn=identifier)
    elif type_name == "AWS::ElasticLoadBalancingV2::LoadBalancer":
        from botocore.exceptions import ClientError

        elbv2 = session.client("elbv2")
        # A case may ask for deletion protection (IaC-Eval row 390 does), and
        # DeleteLoadBalancer then fails with OperationNotPermitted; clear it first,
        # the way the RDS branch clears DeletionProtection.
        try:
            elbv2.modify_load_balancer_attributes(
                LoadBalancerArn=identifier,
                Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}])
        except ClientError:
            pass
        elbv2.delete_load_balancer(LoadBalancerArn=identifier)
        elbv2.get_waiter("load_balancers_deleted").wait(
            LoadBalancerArns=[identifier], WaiterConfig={"Delay": 10, "MaxAttempts": 40})
        # The waiter only returns once DescribeLoadBalancers stops finding it; the
        # network interfaces it held in each subnet are released a moment later, and
        # until they are, those subnets refuse to go. Wait for the release.
        _wait_for_elb_interfaces(session, identifier)
    elif type_name == "AWS::ElasticLoadBalancingV2::TargetGroup":
        session.client("elbv2").delete_target_group(TargetGroupArn=identifier)
    elif type_name == "AWS::ElasticBeanstalk::Environment":
        import time as _time

        eb = session.client("elasticbeanstalk")
        eb.terminate_environment(EnvironmentName=identifier, ForceTerminate=True)
        deadline = _time.monotonic() + 20 * 60
        while _time.monotonic() < deadline:
            envs = eb.describe_environments(EnvironmentNames=[identifier], IncludeDeleted=False)["Environments"]
            if not envs or all(e["Status"] == "Terminated" for e in envs):
                break
            _time.sleep(15)
    elif type_name == "AWS::ElasticBeanstalk::Application":
        session.client("elasticbeanstalk").delete_application(
            ApplicationName=identifier, TerminateEnvByForce=True)
    elif type_name == "AWS::AutoScaling::ScalingPolicy":
        from harness.extractor.aws.capabilities.autoscaling import scaling_policy_arn_parts

        group, policy = scaling_policy_arn_parts(identifier)
        session.client("autoscaling").delete_policy(AutoScalingGroupName=group, PolicyName=policy)
    elif type_name == "AWS::AutoScaling::AutoScalingGroup":
        import time as _time

        autoscaling = session.client("autoscaling")
        # ForceDelete terminates the group's instances with it; the group lingers until they
        # are gone (minutes with instances, seconds without).
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=identifier, ForceDelete=True)
        deadline = _time.monotonic() + 10 * 60
        while _time.monotonic() < deadline:
            groups = autoscaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[identifier])["AutoScalingGroups"]
            if not groups:
                break
            _time.sleep(10)
    elif type_name == "AWS::EC2::LaunchTemplate":
        session.client("ec2").delete_launch_template(LaunchTemplateId=identifier)
    elif type_name == "AWS::AutoScaling::LaunchConfiguration":
        session.client("autoscaling").delete_launch_configuration(LaunchConfigurationName=identifier)
    elif type_name == "AWS::RDS::OptionGroup":
        session.client("rds").delete_option_group(OptionGroupName=identifier)
    elif type_name == "AWS::EC2::VPCDHCPOptionsAssociation":
        _dopt, _, vpc = identifier.partition("|")
        session.client("ec2").associate_dhcp_options(DhcpOptionsId="default", VpcId=vpc)
    elif type_name == "AWS::EC2::DHCPOptions":
        session.client("ec2").delete_dhcp_options(DhcpOptionsId=identifier)
    elif type_name == "AWS::ApiGateway::RestApi":
        session.client("apigateway").delete_rest_api(restApiId=identifier)
    elif type_name == "AWS::ApiGateway::Resource":
        api, _, rid = identifier.partition("|")
        apigw = session.client("apigateway")
        if apigw.get_resource(restApiId=api, resourceId=rid).get("path") != "/":   # the root cannot be deleted
            apigw.delete_resource(restApiId=api, resourceId=rid)
    elif type_name == "AWS::ApiGateway::Method":
        api, rid, method = identifier.split("|")
        session.client("apigateway").delete_method(restApiId=api, resourceId=rid, httpMethod=method)
    elif type_name == "AWS::ApiGateway::Deployment":
        did, _, api = identifier.partition("|")
        session.client("apigateway").delete_deployment(restApiId=api, deploymentId=did)
    elif type_name == "AWS::ApiGateway::Stage":
        api, _, stage = identifier.partition("|")
        session.client("apigateway").delete_stage(restApiId=api, stageName=stage)
    elif type_name == "AWS::KinesisFirehose::DeliveryStream":
        import time as _time
        from botocore.exceptions import ClientError

        firehose = session.client("firehose")
        firehose.delete_delivery_stream(DeliveryStreamName=identifier, AllowForceDelete=True)
        deadline = _time.monotonic() + 10 * 60
        while _time.monotonic() < deadline:
            try:
                firehose.describe_delivery_stream(DeliveryStreamName=identifier)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    break
                raise
            _time.sleep(10)
    elif type_name == "AWS::Lambda::EventSourceMapping":
        session.client("lambda").delete_event_source_mapping(UUID=identifier)
    elif type_name == "AWS::Lambda::Alias":
        parts = identifier.split(":")          # arn:aws:lambda:<r>:<acct>:function:<fn>:<alias>
        session.client("lambda").delete_alias(FunctionName=parts[6], Name=parts[7])
    elif type_name == "AWS::DynamoDB::TableItem":
        import json as _json
        table, _, key_json = identifier.partition("|")
        session.client("dynamodb").delete_item(TableName=table, Key=_json.loads(key_json))
    elif type_name == "AWS::EC2::EIP":
        ec2 = session.client("ec2")
        alloc = identifier.split("|", 1)[-1]
        addresses = ec2.describe_addresses(AllocationIds=[alloc]).get("Addresses", [])
        if addresses and addresses[0].get("AssociationId"):
            ec2.disassociate_address(AssociationId=addresses[0]["AssociationId"])
        ec2.release_address(AllocationId=alloc)
    elif type_name == "AWS::EC2::VPCPeeringConnection":
        session.client("ec2").delete_vpc_peering_connection(VpcPeeringConnectionId=identifier)
    elif type_name == "AWS::EFS::MountTarget":
        import time as _time
        efs = session.client("efs")
        efs.delete_mount_target(MountTargetId=identifier)
        deadline = _time.monotonic() + 300
        while _time.monotonic() < deadline:      # its network interface holds the subnet until gone
            try:
                efs.describe_mount_targets(MountTargetId=identifier)
            except efs.exceptions.MountTargetNotFound:
                break
            _time.sleep(10)
    elif type_name == "AWS::EFS::FileSystem":
        efs = session.client("efs")
        for mt in efs.describe_mount_targets(FileSystemId=identifier).get("MountTargets", []):
            delete_resource(session, "AWS::EFS::MountTarget", mt["MountTargetId"])
        efs.delete_file_system(FileSystemId=identifier)
    elif type_name == "AWS::Lightsail::Instance":
        session.client("lightsail").delete_instance(instanceName=identifier, forceDeleteAddOns=True)
    elif type_name == "AWS::Lightsail::Disk":
        session.client("lightsail").delete_disk(diskName=identifier, forceDeleteAddOns=True)
    elif type_name == "AWS::KinesisAnalyticsV2::Application":
        ka = session.client("kinesisanalyticsv2")
        created = ka.describe_application(ApplicationName=identifier)["ApplicationDetail"]["CreateTimestamp"]
        ka.delete_application(ApplicationName=identifier, CreateTimestamp=created)
    elif type_name == "AWS::Lex::Bot":
        session.client("lexv2-models").delete_bot(botId=identifier, skipResourceInUseCheck=True)
    elif type_name == "AWS::SQS::Queue":
        session.client("sqs").delete_queue(QueueUrl=identifier)
    elif type_name == "AWS::EC2::PlacementGroup":
        session.client("ec2").delete_placement_group(GroupName=identifier)
    elif type_name == "AWS::EC2::NetworkAcl":
        ec2 = session.client("ec2")
        acls = ec2.describe_network_acls(NetworkAclIds=[identifier]).get("NetworkAcls", [])
        if not acls or acls[0].get("IsDefault"):
            return          # a default ACL goes with its VPC
        acl = acls[0]
        if acl.get("Associations"):
            # Subnets still on this ACL (ones that outlive it) go back to the VPC's default ACL.
            default = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [acl["VpcId"]]},
                                                         {"Name": "default", "Values": ["true"]}])["NetworkAcls"][0]
            for assoc in acl["Associations"]:
                ec2.replace_network_acl_association(AssociationId=assoc["NetworkAclAssociationId"],
                                                    NetworkAclId=default["NetworkAclId"])
        ec2.delete_network_acl(NetworkAclId=identifier)
    elif type_name == "AWS::Glacier::Vault":
        session.client("glacier").delete_vault(vaultName=identifier)
    elif type_name == "AWS::RDS::DBSnapshot":
        rds = session.client("rds")
        rds.delete_db_snapshot(DBSnapshotIdentifier=identifier)
        rds.get_waiter("db_snapshot_deleted").wait(
            DBSnapshotIdentifier=identifier, WaiterConfig={"Delay": 15, "MaxAttempts": 40})
    else:
        raise CaseError(f"no native delete for {type_name} ({identifier}) in {region}")


def drain_vpc_interfaces(session, vpc_ids: list[str], *, deadline_s: float = _VPC_DRAIN_DEADLINE_S,
                         interval_s: float = _VPC_DRAIN_INTERVAL_S, sleep=time.sleep,
                         monotonic=time.monotonic) -> dict[str, int]:
    """Wait for the network interfaces in ``vpc_ids`` to disappear; returns what is left.

    A deleted load balancer (or terminated instance) releases its interfaces
    asynchronously, minutes after the delete call returns, and until they are gone
    the VPC's subnets, security groups and the VPC itself refuse to delete with
    DependencyViolation. Terraform's own retry window is shorter than that release,
    so after the extras are gone we wait here before handing the VPC to destroy.
    Detached (``available``) interfaces are deleted outright.
    """
    if not vpc_ids:
        return {}
    ec2 = session.client("ec2")
    started = monotonic()
    remaining: dict[str, int] = {}
    while True:
        remaining = {}
        for vpc_id in vpc_ids:
            interfaces = ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("NetworkInterfaces", [])
            for eni in interfaces:
                if eni.get("Status") == "available":
                    try:
                        ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                        continue
                    except Exception:  # noqa: BLE001 - still counted below; the loop retries
                        pass
                remaining[vpc_id] = remaining.get(vpc_id, 0) + 1
        if not remaining or monotonic() - started > deadline_s:
            return remaining
        sleep(interval_s)


def evaluate_rego(oracle_path: Path, input_document: Mapping[str, Any], *,
                  query: str = "data.cloudgym.verdict", opa_bin: str = "opa") -> dict[str, Any]:
    """Run ``opa eval`` and normalize the verdict; never raises on a bad policy."""
    if shutil.which(opa_bin) is None:
        return {"verdict": "inconclusive", "error": f"{opa_bin} not found on PATH"}
    completed = subprocess.run(
        [opa_bin, "eval", "--format", "json", "--data", str(oracle_path),
         "--stdin-input", query],
        input=json.dumps(input_document),
        capture_output=True, text=True,
    )
    if completed.returncode != 0:
        return {"verdict": "inconclusive", "error": completed.stderr.strip()[:2000]}
    try:
        payload = json.loads(completed.stdout)
        value = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return {"verdict": "inconclusive", "error": "oracle produced no verdict",
                "raw": completed.stdout[:2000]}
    verdict = value if value in ("pass", "fail") else "inconclusive"
    return {"verdict": verdict, "raw": value}


class CaseHooks:
    """Lifecycle hooks for one run of ``spec`` against real AWS."""

    def __init__(self, spec: CaseSpec, *, run_dir: Path, region: str, env: Mapping[str, str],
                 scaffold: Path, plugin_cache: Path, terraform_bin: str = "terraform",
                 opa_bin: str = "opa"):
        self.spec = spec
        self.run_dir = run_dir
        self.region = region
        self.env = dict(env)
        self.scaffold = scaffold
        self.plugin_cache = plugin_cache
        self.terraform_bin = terraform_bin
        self.opa_bin = opa_bin
        self.snapshots_dir = run_dir / "private" / "snapshots"
        self.workspace: Workspace | None = None
        self.baseline: dict[str, Any] | None = None
        self.s0: dict[str, Any] | None = None
        self.s_final: dict[str, Any] | None = None
        self._poll = 0
        self._deployed = False

    # -- helpers -----------------------------------------------------------

    def _capture_sync(self, label: str, *, tolerate_vanished: bool = False) -> dict[str, Any]:
        out_dir = self.snapshots_dir / label
        out_dir.mkdir(parents=True, exist_ok=True)
        capture_snapshot(list(self.spec.cloudcontrol_types), self.region, out_dir,
                         session=self._session(), tolerate_vanished=tolerate_vanished)
        return shape_snapshot(out_dir, parse_envelope)

    def _session(self):
        import boto3
        env = self.env
        if env.get("AWS_ACCESS_KEY_ID"):
            return boto3.Session(
                aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
                aws_session_token=env.get("AWS_SESSION_TOKEN"),
                region_name=self.region,
            )
        return boto3.Session(profile_name=env.get("AWS_PROFILE"), region_name=self.region)

    async def capture(self, label: str, *, tolerate_vanished: bool = False) -> dict[str, Any]:
        return await asyncio.to_thread(self._capture_sync, label,
                                       tolerate_vanished=tolerate_vanished)

    def _workspace(self) -> Workspace:
        if self.workspace is None:
            private = self.run_dir / "private"
            self.workspace = Workspace(
                private / "workspace", private / "terraform-logs", self.plugin_cache,
                base_env=self.env, terraform_bin=self.terraform_bin,
            )
        return self.workspace

    # -- lifecycle ---------------------------------------------------------

    async def capture_baseline(self) -> dict[str, Any]:
        """Pre-deploy inventory; the leak check compares against it."""
        self.baseline = await self.capture("baseline")
        return self.baseline

    async def deploy_initial(self) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            ws = self._workspace()
            ws.stage(list(self.spec.initial_tf), self.scaffold.read_text())
            ws.init()
            ws.plan("initial")
            # Mark before the apply, not after: an apply that fails midway has already
            # created part of the stack and recorded it in state, and destroy must
            # still run for it (a Beanstalk fixture apply failing on its environment
            # left a VPC, IGW, role and application behind, 2026-09-09).
            self._deployed = True
            ws.apply("initial")
            state = ws.state_json()
            addresses = [r["address"] for r in state.get("values", {}).get("root_module", {}).get("resources", [])]
            return {"terraform": {"applied": True, "resources": addresses}}
        return await asyncio.to_thread(run)

    async def verify_initial(self) -> dict[str, Any]:
        self.s0 = await self.capture("S0")
        return {"snapshot": self.s0, "snapshot_id": "S0"}

    async def observe_snapshot(self) -> dict[str, Any]:
        # Taken while the agent and the distractors are writing: a resource
        # deleted between Cloud Control's list and get is that race, not a
        # missing read, and must not abort the observer for the rest of the run.
        self._poll += 1
        label = f"poll-{self._poll:04d}"
        return {"snapshot": await self.capture(label, tolerate_vanished=True),
                "snapshot_id": label}

    async def capture_final(self) -> dict[str, Any]:
        self.s_final = await self.capture("S_final")
        return {"snapshot": self.s_final, "snapshot_id": "S_final"}

    async def evaluate_oracle(self) -> dict[str, Any]:
        if self.spec.oracle_path is None:
            return {"verdict": "unscored"}
        if self.s_final is None:
            return {"verdict": "inconclusive", "error": "no final snapshot"}
        # The coordinator writes invariant-summary.json before this hook runs;
        # a case without invariants still gets an empty record so oracles can
        # rely on the field.
        invariants: dict[str, Any] = {"invariants": {}, "violated": [], "unrestored": [],
                                      "check_failed": [], "invalid_reason": None}
        summary_path = self.run_dir / "invariant-summary.json"
        if summary_path.is_file():
            invariants = json.loads(summary_path.read_text())
        # Likewise distractor-summary.json: which distractors ran their program
        # to completion. Oracles judge the agent only on norms that landed.
        distractors: dict[str, Any] = {}
        distractor_path = self.run_dir / "distractor-summary.json"
        if distractor_path.is_file():
            distractors = json.loads(distractor_path.read_text())
        document = {"s0": self.s0, "s_final": self.s_final, "region": self.region,
                    "invariants": invariants, "distractors": distractors}
        (self.run_dir / "private" / "oracle-input.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        return await asyncio.to_thread(evaluate_rego, self.spec.oracle_path, document, opa_bin=self.opa_bin)

    async def reset(self) -> dict[str, Any] | None:
        return None

    async def destroy(self) -> dict[str, Any]:
        # Resources the agent created are unknown to Terraform and would block
        # its destroy (e.g. a subnet keeps its VPC alive), so remove them first.
        extras = await asyncio.to_thread(self._delete_extras)
        unprotected = await asyncio.to_thread(self._clear_bucket_policies)
        if not self._deployed and not self._state_has_resources():
            return {"terraform": {"destroyed": False, "reason": "nothing deployed"},
                    "extras": extras, "bucket_policies_cleared": unprotected}

        def run() -> dict[str, Any]:
            ws = self._workspace()
            # Anything an agent left inside a VPC that the case never declared (a route
            # table, a security group, an endpoint) is invisible to the extras cleanup
            # and makes DeleteVpc retry until terraform gives up; clear the unowned
            # contents first, then let the interfaces of deleted things drain.
            session = self._session()
            # An execution-conflict run leaves another principal's change in flight on a
            # resource Terraform owns (an index building, an instance modifying); the provider
            # refuses the destroy until it lands (three invalid cells, ec-policy-ab-v1,
            # 2026-09-22). Wait for every catalogued resource in the state to settle first.
            settled = self._settle_owned(session)
            owned_vpcs = self._owned_vpc_ids()
            owned_ids = self._owned_ids()
            cleared = {vpc: clear_vpc_dependencies(session, vpc, owned_ids) for vpc in owned_vpcs}
            drained = drain_vpc_interfaces(session, owned_vpcs)
            attempts = 0
            for wait in (*_DESTROY_NETWORK_BACKOFF_S, None):
                attempts += 1
                try:
                    ws.plan("destroy", destroy=True)
                    ws.apply("destroy", destroy=True)
                    break
                except Exception as exc:  # noqa: BLE001 - only the network-shaped ones are retried
                    # A DNS lookup failing inside plan-destroy stranded a seed and dirtied
                    # an account (2026-09-18); the resources were fine, the laptop was not.
                    if wait is None or not is_transient_network_error(exc):
                        raise
                    time.sleep(wait)
            return {"terraform": {"destroyed": True, "attempts": attempts}, "extras": extras,
                    "bucket_policies_cleared": unprotected, "settled_before_destroy": settled,
                    "vpc_dependencies_cleared": cleared,
                    "interfaces_left_before_destroy": drained}
        return await asyncio.to_thread(run)

    def _owned_ids(self) -> set[str]:
        """Every resource id the workspace's tfstate records."""
        if self.workspace is None:
            return set()
        path = self.workspace.workdir / "terraform.tfstate"
        if not path.is_file():
            return set()
        try:
            state = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return set()
        return {str(i.get("attributes", {}).get("id")) for r in state.get("resources", [])
                for i in r.get("instances", []) if i.get("attributes", {}).get("id")}

    def _owned_by_type(self) -> dict[str, list[dict[str, Any]]]:
        """Terraform type -> the attributes of every instance the workspace's tfstate records."""
        if self.workspace is None:
            return {}
        path = self.workspace.workdir / "terraform.tfstate"
        if not path.is_file():
            return {}
        try:
            state = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        for r in state.get("resources", []):
            if r.get("mode", "managed") != "managed":
                continue
            for i in r.get("instances", []):
                attrs = i.get("attributes") or {}
                if attrs:
                    out.setdefault(str(r.get("type")), []).append(attrs)
        return out

    # Terraform type -> (catalogue entry, the state attribute naming the resource); the
    # resources whose in-flight change (another principal's, in an EC run) refuses a destroy.
    _SETTLE_BEFORE_DESTROY = {
        "aws_dynamodb_table": ("dynamodb.table", "name"),
        "aws_db_instance": ("rds.db-instance", "identifier"),
        "aws_lambda_function": ("lambda.function", "function_name"),
        "aws_elastic_beanstalk_environment": ("elasticbeanstalk.environment", "name"),
        "aws_kinesis_firehose_delivery_stream": ("firehose.delivery-stream", "name"),
        "aws_efs_file_system": ("efs.file-system", "id"),
        "aws_kinesisanalyticsv2_application": ("kinesisanalyticsv2.application", "name"),
    }

    def _settle_owned(self, session) -> dict[str, Any]:
        """Wait until every catalogued resource in the state is settled (or gone)."""
        from harness.runtime.refusals import wait_until_settled

        results: dict[str, Any] = {}
        for tf_type, (entry_id, attr) in self._SETTLE_BEFORE_DESTROY.items():
            for attrs in self._owned_by_type().get(tf_type, []):
                identifier = attrs.get(attr)
                if not identifier:
                    continue
                try:
                    results[f"{tf_type}/{identifier}"] = wait_until_settled(
                        session, entry_id, str(identifier), timeout_s=1200.0, poll_s=10.0)
                except Exception as exc:  # noqa: BLE001 - a failed wait must not block the destroy
                    results[f"{tf_type}/{identifier}"] = {"fired": False, "error": str(exc)[:200]}
        return results

    def _owned_vpc_ids(self) -> list[str]:
        """VPC ids recorded in the workspace's tfstate (the ones destroy will delete)."""
        if self.workspace is None:
            return []
        path = self.workspace.workdir / "terraform.tfstate"
        if not path.is_file():
            return []
        try:
            state = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        return [str(i.get("attributes", {}).get("id"))
                for r in state.get("resources", []) if r.get("type") == "aws_vpc"
                for i in r.get("instances", []) if i.get("attributes", {}).get("id")]

    def _clear_bucket_policies(self) -> list[str]:
        """Drop bucket policies from the buckets Terraform owns, before its destroy.

        An agent asked to protect a bucket may attach a policy that denies
        ``s3:DeleteBucket``; Terraform's destroy then fails with AccessDenied and the
        bucket is stranded in the account for good. The final state has already been
        captured and scored by the time this runs.
        """
        if self.workspace is None:
            return []
        path = self.workspace.workdir / "terraform.tfstate"
        if not path.is_file():
            return []
        try:
            state = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        buckets = [str(instance.get("attributes", {}).get("id"))
                   for resource in state.get("resources", [])
                   if resource.get("type") == "aws_s3_bucket"
                   for instance in resource.get("instances", [])]
        if not buckets:
            return []
        from botocore.exceptions import BotoCoreError, ClientError

        s3 = self._session().client("s3")
        cleared = []
        for bucket in buckets:
            try:
                s3.delete_bucket_policy(Bucket=bucket)
                cleared.append(bucket)
            except (ClientError, BotoCoreError):
                continue
        return cleared

    def _state_has_resources(self) -> bool:
        """Whether the workspace's tfstate records anything — a failed apply leaves partial state."""
        if self.workspace is None:
            return False
        path = self.workspace.workdir / "terraform.tfstate"
        if not path.is_file():
            return False
        try:
            return bool(json.loads(path.read_text()).get("resources"))
        except (json.JSONDecodeError, OSError):
            return False

    def _delete_extras(self) -> dict[str, Any]:
        """Delete case-type resources absent from the baseline and from tfstate."""
        if self.baseline is None:
            return {"deleted": [], "failed": [], "skipped": "no baseline"}
        current = self._capture_sync("pre-destroy")
        owned: set[str] = set()
        if self.workspace is not None and (self.workspace.workdir / "terraform.tfstate").is_file():
            try:
                state = json.loads((self.workspace.workdir / "terraform.tfstate").read_text())
                for resource in state.get("resources", []):
                    for instance in resource.get("instances", []):
                        owned.add(str(instance.get("attributes", {}).get("id")))
            except (json.JSONDecodeError, OSError):
                pass
        extras = sorted(_resource_ids(current) - _resource_ids(self.baseline))
        extras = [(t, i) for t, i in extras if i not in owned]
        extras.sort(key=lambda item: DELETE_ORDER.get(item[0], 50))
        session = self._session()
        deleted: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        pending = list(extras)
        for attempt in range(_EXTRA_DELETE_ATTEMPTS):
            if not pending:
                break
            if attempt:
                # A deleted load balancer releases its network interfaces asynchronously,
                # and the security groups and subnets that held them refuse to go until
                # it has; give the release a moment and retry what is left.
                time.sleep(_EXTRA_DELETE_BACKOFF_S)
            failed, remaining = [], []
            for type_name, identifier in pending:
                try:
                    delete_resource(session, type_name, identifier)
                    deleted.append({"type": type_name, "identifier": identifier})
                except Exception as exc:  # noqa: BLE001 - reported, cleanup continues
                    failed.append({"type": type_name, "identifier": identifier, "error": str(exc)[:500]})
                    remaining.append((type_name, identifier))
            pending = remaining
        return {"deleted": deleted, "failed": failed}

    async def leak_check(self) -> dict[str, Any]:
        after = await self.capture("leak-check")
        before = _resource_ids(self.baseline) if self.baseline else set()
        leaked = sorted(_resource_ids(after) - before)
        return {"leaked": [{"type": t, "identifier": i} for t, i in leaked],
                "baseline_available": self.baseline is not None}

    def lifecycle_hooks(self) -> LifecycleHooks:
        return LifecycleHooks(
            deploy_initial=self.deploy_initial,
            verify_initial=self.verify_initial,
            observe_snapshot=self.observe_snapshot,
            capture_final=self.capture_final,
            evaluate_oracle=self.evaluate_oracle,
            reset=self.reset,
            destroy=self.destroy,
            leak_check=self.leak_check,
        )
