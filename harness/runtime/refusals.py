"""The refusal catalogue: which provider state machines refuse which operations, and how to
observe them. Backs the execution-conflict (EC) case type.

An entry is one resource's state machine. The parts that come from the installed SDK are
derived here, not authored:

- the **observing read** and the **settled state** are the waiter's operation, JMESPath
  argument and success value (``waiters-2.json``);
- the **terminal states** are the waiter's failure acceptors, so a wait can abort;
- the **refusing operations** are every operation of the service that declares one of the
  entry's error shapes (``service-2.json``); the shapes themselves are a hand-reviewed
  allowlist per entry, checked to exist in the model.

Three families lack a waiter (Auto Scaling, SQS) or declare no errors at all (EC2) and carry
those parts by hand, marked ``source: manual`` and cited. The built catalogue is committed as
``seeds/refusals.json`` (``uv run refusals build``); ``load()`` reads it, and the two wait
helpers below let a distractor program hold the proxy's release until the resource is
observably busy, and let teardown wait until it is settled again.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import botocore.session
import jmespath

SCHEMA_VERSION = 1
CATALOGUE_PATH = Path(__file__).resolve().parents[2] / "seeds" / "refusals.json"


@dataclass(frozen=True)
class Observation:
    """One read that reports the resource's state."""
    operation: str            # e.g. DescribeDBInstances
    identifier_param: str     # the input member that names the resource, e.g. DBInstanceIdentifier
    path: str                 # JMESPath into the response, e.g. DBInstances[].DBInstanceStatus
    settled: str              # the value that means "not busy"
    terminal: tuple[str, ...] = ()   # values after which the resource will never settle (waiter failures)
    absent_error: str | None = None  # error code meaning "gone" (a retry acceptor on the waiter)
    waiter: str | None = None
    delay_s: int | None = None
    max_attempts: int | None = None
    source: str = "sdk"              # "manual": hand-written where the SDK's waiter is blind


@dataclass(frozen=True)
class Entry:
    id: str
    service: str                       # botocore service name
    resource: str                      # Cloud Control type name
    source: str                        # "sdk" | "manual"
    observe: tuple[Observation, ...]   # empty for entries without an observable state (SQS)
    refusals: dict[str, tuple[str, ...]]   # error shape -> operations that declare it
    codes: dict[str, str] = field(default_factory=dict)   # error shape -> the code on the wire
    aliases: tuple[str, ...] = ()      # other wire codes observed for the same refusal (cited in notes)
    window_s: int | None = None        # fixed window when there is no state to observe
    settle: str | None = None          # teardown: the resource must be settled before delete
    # What real runs showed: {operation, change, refused, case, date}. The SDK's declared
    # errors over-approximate what the provider refuses; a pair a certified run falsified is
    # excluded from refusing_operations(), one it confirmed is kept as evidence.
    evidence: tuple[Mapping[str, Any], ...] = ()
    notes: str = ""
    citation: str = ""

    def refusing_operations(self) -> set[str]:
        return {op for ops in self.refusals.values() for op in ops} - set(self.falsified())

    def falsified(self) -> dict[str, Mapping[str, Any]]:
        """Operations no real run has seen refused while some run showed them going through.

        Evidence is per (operation, in-flight change): an operation refused under one change
        and accepted under another (DynamoDB's UpdateTable during TableStatus UPDATING versus
        during an index backfill) stays refusable; the notes say which change opens the window.
        """
        confirmed = {e["operation"] for e in self.evidence if e.get("refused") is True}
        return {e["operation"]: e for e in self.evidence
                if e.get("refused") is False and e["operation"] not in confirmed}

    def wire_codes(self, operation: str | None = None) -> set[str]:
        """The error codes a refusal of ``operation`` (any, when None) arrives with."""
        shapes = [s for s, ops in self.refusals.items() if operation is None or operation in ops]
        return {self.codes.get(s, s) for s in shapes} | (set(self.aliases) if shapes else set())

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "service": self.service, "resource": self.resource, "source": self.source,
                "observe": [asdict(o) for o in self.observe],
                "refusals": {k: list(v) for k, v in self.refusals.items()},
                "codes": dict(self.codes), "aliases": list(self.aliases),
                "window_s": self.window_s, "settle": self.settle, "notes": self.notes, "citation": self.citation,
                "evidence": [dict(e) for e in self.evidence]}


# -- families -------------------------------------------------------------------------
#
# What is hand-chosen per family: the waiter(s) to read state from, the input member that
# names the resource, and the error shapes that mean "not now". Everything else is read
# from the SDK at build time.

@dataclass(frozen=True)
class Family:
    id: str
    service: str
    resource: str
    waiters: tuple[tuple[str, str], ...]        # (waiter name, identifier param)
    shapes: tuple[str, ...]                     # error shapes meaning "not in the required state"
    settle: str | None = None
    notes: str = ""
    manual: Mapping[str, Any] | None = None     # parts the SDK lacks, with a citation
    aliases: tuple[str, ...] = ()               # wire codes seen in real runs for the same refusal
    # Observations the SDK's waiter misses, added to an otherwise SDK-derived entry; each is
    # marked source "manual" on the observation, the entry itself stays "sdk".
    extra_observe: tuple[Mapping[str, Any], ...] = ()
    evidence: tuple[Mapping[str, Any], ...] = ()   # from certified runs (see Entry.evidence)


FAMILIES: tuple[Family, ...] = (
    Family("rds.db-instance", "rds", "AWS::RDS::DBInstance",
           waiters=(("DBInstanceAvailable", "DBInstanceIdentifier"),),
           shapes=("InvalidDBInstanceStateFault",), settle="rds.db-instance",
           notes="modifying / backing-up / rebooting refuse modification, snapshot and read-replica creation; "
                 "the SCP denies Multi-AZ, so the in-flight change is a class or storage change, a reboot "
                 "or a manual snapshot"),
    Family("rds.db-cluster", "rds", "AWS::RDS::DBCluster",
           waiters=(("DBClusterAvailable", "DBClusterIdentifier"),),
           shapes=("InvalidDBClusterStateFault",), settle="rds.db-cluster",
           notes="Aurora; no adapter yet (aws_rds_cluster is billable), listed for completeness"),
    Family("dynamodb.table", "dynamodb", "AWS::DynamoDB::Table",
           waiters=(("TableExists", "TableName"),),
           shapes=("ResourceInUseException", "LimitExceededException"), settle="dynamodb.table",
           notes="UPDATING (an index being built) refuses a second UpdateTable; only one index change per "
                 "table at a time; a table being deleted refuses recreation under its name. The SDK waiter "
                 "reads TableStatus only, which returns to ACTIVE while an index is still backfilling (pilot "
                 "iac-eval-165-dynamodb-table-002, 2026-09-22), so a manual observation counts the indexes "
                 "not yet ACTIVE; that read marks busy for a second index operation (LimitExceededException), "
                 "NOT for a throughput UpdateTable, which is refused only while TableStatus is UPDATING "
                 "(ec-cycles-ab-v1, 2026-09-23)",
           extra_observe=({"operation": "DescribeTable", "identifier_param": "TableName",
                           "path": "length(Table.GlobalSecondaryIndexes[?IndexStatus!='ACTIVE'] || `[]`)",
                           "settled": "0", "absent_error": "ResourceNotFoundException"},),
           evidence=(
               {"operation": "UpdateTable", "change": "another principal switching encryption to the AWS-managed KMS key", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.1, "note": "an SSE switch does not hold the table in UPDATING against a stream change"},
               {"operation": "UpdateTable", "change": "another principal enabling point-in-time recovery", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.0},
               {"operation": "UpdateTable", "change": "another principal's global secondary index build",
                "refused": True, "code": "ResourceInUseException", "waited_s": 514,
                "case": "iac-eval-165-dynamodb-table-002", "date": "2026-09-22"},
               {"operation": "UpdateTimeToLive", "change": "another principal's global secondary index build",
                "refused": False, "case": "iac-eval-165-dynamodb-table-002", "date": "2026-09-22",
                "note": "declared in the SDK, but the call succeeded 0.3 s into the build with the table UPDATING"},
               {"operation": "UpdateTable", "change": "an index backfilling with the table already ACTIVE again",
                "refused": False, "case": "ec-cycles-ab-v1", "date": "2026-09-23",
                "note": "the window is TableStatus UPDATING only, 30-75 s after the index create; the backfill "
                        "runs ~8 min more with the table ACTIVE and a throughput UpdateTable then goes through "
                        "(agents that polled until the index read ACTIVE waited ~500 s for nothing)"},
               {"operation": "UpdateTable", "change": "a throughput step on another owner's index (index UPDATING, table ACTIVE)",
                "refused": False, "case": "ec-cycles-ab-v1", "date": "2026-09-23",
                "note": "k3 variant firing 2: busy by the index read, the held UpdateTable was released and succeeded"},
           )),
    Family("lambda.function", "lambda", "AWS::Lambda::Function",
           waiters=(("FunctionActive", "FunctionName"), ("FunctionUpdated", "FunctionName")),
           shapes=("ResourceConflictException",), settle="lambda.function",
           notes="State Pending (a VPC-attached function being created) and LastUpdateStatus InProgress "
                 "refuse configuration and code updates"),
    Family("route53.change", "route53", "AWS::Route53::RecordSet",
           waiters=(("ResourceRecordSetsChanged", "Id"),),
           shapes=("PriorRequestNotComplete",), aliases=("Throttling",),
           evidence=(
               {"operation": "ChangeResourceRecordSets", "change": "another principal's change batch PENDING "
                "(propagating) in the same hosted zone", "refused": False,
                "case": "iac-eval-84-route53-record-002", "date": "2026-09-22",
                "note": "two batches observed PENDING, the agent's held change released into each and accepted; "
                        "Route 53 refuses only while a request is still being accepted (milliseconds), not while "
                        "an accepted batch propagates"},
           ),
           notes="a change batch PENDING on a record set refuses the next change to it; the observing read "
                 "takes the change id the first ChangeResourceRecordSets returned. Alias: Route 53 also "
                 "answers with Throttling 'The request was rejected because Route 53 was still processing a "
                 "prior request' (seen in consult-0-ctl-v1, 2026-09-19); match that code with that message"),
    Family("elbv2.load-balancer", "elbv2", "AWS::ElasticLoadBalancingV2::LoadBalancer",
           waiters=(("LoadBalancerAvailable", "LoadBalancerArns"),),
           shapes=("ResourceInUseException", "OperationNotPermittedException"),
           notes="provisioning; the identifier param is a list (LoadBalancerArns)",
           evidence=(
               {"operation": "ModifyLoadBalancerAttributes", "change": "the network load balancer provisioning", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.1},
               {"operation": "SetSubnets", "change": "the network load balancer provisioning", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.3},
               {"operation": "CreateListener", "change": "the network load balancer provisioning", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.1, "note": "provisioning refuses none of the three; the family has no confirmed EC window"},
           )),
    Family("elasticbeanstalk.environment", "elasticbeanstalk", "AWS::ElasticBeanstalk::Environment",
           waiters=(("EnvironmentUpdated", "EnvironmentNames"),),
           shapes=("OperationInProgressException",), settle="elasticbeanstalk.environment",
           notes="Updating refuses a second update; slow family (rule 5); the identifier param is a list"),
    Family("firehose.delivery-stream", "firehose", "AWS::KinesisFirehose::DeliveryStream",
           waiters=(), shapes=("ResourceInUseException", "ConcurrentModificationException"),
           settle="firehose.delivery-stream",
           notes="the errors are in the SDK; Firehose ships no waiters, so the observing reads are manual. "
                 "A stream is busy while CREATING, and an ACTIVE stream while its server-side encryption is "
                 "ENABLING or DISABLING (Start/StopDeliveryStreamEncryption); ConcurrentModificationException "
                 "is UpdateDestination's stale CurrentDeliveryStreamVersionId after another principal's update",
           manual={"observe": [
                       {"operation": "DescribeDeliveryStream", "identifier_param": "DeliveryStreamName",
                        "path": "DeliveryStreamDescription.DeliveryStreamStatus", "settled": "ACTIVE",
                        "terminal": ["CREATING_FAILED", "DELETING_FAILED"],
                        "absent_error": "ResourceNotFoundException"},
                       {"operation": "DescribeDeliveryStream", "identifier_param": "DeliveryStreamName",
                        "path": "contains(`[\"ENABLING\", \"DISABLING\"]`, "
                                "DeliveryStreamDescription.DeliveryStreamEncryptionConfiguration.Status || 'NONE')",
                        "settled": "False", "absent_error": "ResourceNotFoundException"}],
                   "citation": "https://docs.aws.amazon.com/firehose/latest/APIReference/API_StartDeliveryStreamEncryption.html"}),
    # -- EC diversity batch (2026-09-23): refusals the SDK declares, state reads the SDK lacks.
    Family("lambda.event-source-mapping", "lambda", "AWS::Lambda::EventSourceMapping",
           waiters=(), shapes=("ResourceInUseException",),
           notes="a mapping refuses Update/DeleteEventSourceMapping while it moves (Creating, Enabling, "
                 "Disabling, Updating, Deleting); Lambda ships no mapping waiter, so the read is manual",
           manual={"observe": [{"operation": "GetEventSourceMapping", "identifier_param": "UUID",
                                "path": "contains(`[\"Creating\", \"Enabling\", \"Disabling\", \"Updating\", \"Deleting\"]`, State)",
                                "settled": "False", "absent_error": "ResourceNotFoundException"}],
                   "citation": "https://docs.aws.amazon.com/lambda/latest/api/API_UpdateEventSourceMapping.html"},
           evidence=(
               {"operation": "UpdateEventSourceMapping", "change": "the mapping just created (Creating)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.4},
               {"operation": "UpdateEventSourceMapping", "change": "another principal's batch-size update (Updating)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.3},
               {"operation": "UpdateEventSourceMapping", "change": "another principal disabling the mapping (Disabling)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.4},
               {"operation": "DeleteEventSourceMapping", "change": "another principal re-enabling the mapping (Enabling)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.3, "note": "declared in the SDK, but no mapping transition refused a concurrent update or delete; no EC window"},
           )),
    Family("efs.file-system", "efs", "AWS::EFS::FileSystem",
           waiters=(), shapes=("IncorrectFileSystemLifeCycleState",), settle="efs.file-system",
           notes="a file system refuses lifecycle, policy, backup-policy and throughput changes unless "
                 "available (creating, updating, deleting); EFS ships no waiters",
           manual={"observe": [{"operation": "DescribeFileSystems", "identifier_param": "FileSystemId",
                                "path": "FileSystems[0].LifeCycleState", "settled": "available",
                                "terminal": ["error"], "absent_error": "FileSystemNotFound"}],
                   "citation": "https://docs.aws.amazon.com/efs/latest/ug/API_FileSystemDescription.html"},
           evidence=(
               {"operation": "PutLifecycleConfiguration", "change": "another principal switching throughput to elastic (updating)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "IncorrectFileSystemLifeCycleState", "waited_s": 3.2},
               {"operation": "PutFileSystemPolicy", "change": "the file system being created (creating)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "IncorrectFileSystemLifeCycleState", "waited_s": 6.2, "note": "confirmed, but the window is seconds: a thin EC case, like the Lambda configuration update"},
           )),
    Family("efs.mount-target", "efs", "AWS::EFS::MountTarget",
           waiters=(), shapes=("IncorrectMountTargetState",),
           notes="a mount target refuses security-group changes unless available (creating, updating, deleting)",
           manual={"observe": [{"operation": "DescribeMountTargets", "identifier_param": "MountTargetId",
                                "path": "MountTargets[0].LifeCycleState", "settled": "available",
                                "terminal": ["error"], "absent_error": "MountTargetNotFound"}],
                   "citation": "https://docs.aws.amazon.com/efs/latest/ug/API_MountTargetDescription.html"},
           evidence=(
               {"operation": "ModifyMountTargetSecurityGroups", "change": "the mount target being created (creating)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.6},
               {"operation": "ModifyMountTargetSecurityGroups", "change": "another principal's security-group change", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.6, "note": "declared in the SDK; security-group changes on a creating or updating mount target went through"},
           )),
    Family("ec2.vpc-peering", "ec2", "AWS::EC2::VPCPeeringConnection",
           waiters=(), shapes=(),
           notes="a connection pending acceptance (or provisioning) is not active; EC2's model declares no "
                 "errors, so the refused operations and code come from the probe's evidence",
           manual={"observe": [{"operation": "DescribeVpcPeeringConnections", "identifier_param": "VpcPeeringConnectionIds",
                                "path": "VpcPeeringConnections[0].Status.Code", "settled": "active",
                                "terminal": ["rejected", "failed", "expired", "deleted"],
                                "absent_error": "InvalidVpcPeeringConnectionID.NotFound"}],
                   "refusals": {"OperationNotPermitted": ["ModifyVpcPeeringConnectionOptions"]},
                   "citation": "https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html"},
           evidence=(
               {"operation": "ModifyVpcPeeringConnectionOptions", "change": "the connection pending acceptance by the peer VPC's owner", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "OperationNotPermitted", "waited_s": 25.6, "note": "refused until the peer accepts (accepted at 20 s in the probe); the window is as long as the accepter takes. A first run without DNS hostnames on both VPCs failed permanently with the same code: the case must enable them"},
               {"operation": "CreateRoute", "change": "the connection pending acceptance by the peer VPC's owner", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.2, "note": "a route to a pending connection is accepted"},
           )),
    Family("lightsail.instance", "lightsail", "AWS::Lightsail::Instance",
           waiters=(), shapes=(),
           notes="an instance in transition (pending, stopping, starting, rebooting) refuses stop/start, "
                 "disk attach and snapshots; Lightsail declares its two generic errors on 120-160 operations, "
                 "far too broad, so refused pairs come from probe evidence only",
           manual={"observe": [{"operation": "GetInstance", "identifier_param": "instanceName",
                                "path": "contains(`[\"pending\", \"stopping\", \"starting\", \"rebooting\"]`, instance.state.name)",
                                "settled": "False", "absent_error": "NotFoundException"}],
                   "refusals": {"OperationFailureException": ["AttachDisk", "StopInstance", "StartInstance"]},
                   "citation": "https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_InstanceState.html"},
           evidence=(
               {"operation": "AttachDisk", "change": "another principal stopping the instance (stopping)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "OperationFailureException", "waited_s": 40.5},
               {"operation": "StopInstance", "change": "another principal starting the instance (pending)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "OperationFailureException", "waited_s": 9.3},
           )),
    Family("lightsail.disk", "lightsail", "AWS::Lightsail::Disk",
           waiters=(), shapes=(),
           notes="a disk attaching or detaching (or pending) refuses attach/detach; pairs from probe evidence",
           manual={"observe": [{"operation": "GetDisk", "identifier_param": "diskName",
                                "path": "contains(`[\"attaching\", \"detaching\"]`, disk.attachmentState || 'none')",
                                "settled": "False", "absent_error": "NotFoundException"}],
                   "citation": "https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_Disk.html"},
           evidence=(
               {"operation": "AttachDisk", "change": "another principal detaching the disk (detaching)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 1.2},
           )),
    Family("kinesisanalyticsv2.application", "kinesisanalyticsv2", "AWS::KinesisAnalyticsV2::Application",
           waiters=(), shapes=("ResourceInUseException", "ConcurrentModificationException"),
           settle="kinesisanalyticsv2.application",
           notes="an application refuses updates while STARTING, STOPPING, UPDATING, AUTOSCALING or ROLLING_BACK "
                 "(ResourceInUseException); an update carrying a stale CurrentApplicationVersionId after another "
                 "principal's update fails with ConcurrentModificationException. No waiters",
           manual={"observe": [{"operation": "DescribeApplication", "identifier_param": "ApplicationName",
                                "path": "contains(`[\"STARTING\", \"STOPPING\", \"UPDATING\", \"AUTOSCALING\", \"ROLLING_BACK\", \"FORCE_STOPPING\", \"DELETING\", \"MAINTENANCE\"]`, ApplicationDetail.ApplicationStatus)",
                                "settled": "False", "absent_error": "ResourceNotFoundException"}],
                   "citation": "https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_UpdateApplication.html"},
           evidence=(
               {"operation": "UpdateApplication", "change": "another principal's configuration update on a READY application (UPDATING)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.2, "note": "an update of a non-running application applies at once; ResourceInUseException needs a running one"},
               {"operation": "UpdateApplication", "change": "another principal's update applied after the agent read CurrentApplicationVersionId", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "ConcurrentModificationException", "note": "optimistic concurrency: refused until the agent re-reads the version id (never succeeded with the stale id), the same shape as Firehose's destination version"},
           )),
    Family("lexv2.bot", "lexv2-models", "AWS::Lex::Bot",
           waiters=(("BotAvailable", "botId"),), shapes=("PreconditionFailedException", "ConflictException"),
           notes="a bot Creating, Updating or Versioning (and a locale Building) refuses changes; both errors are "
                 "declared on 40+ operations, so evidence narrows them",
           evidence=(
               {"operation": "UpdateBot", "change": "the bot being created (Creating)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "ValidationException", "waited_s": 3.3, "note": "refused with ValidationException, not a declared shape, for 3 s; only the creator can be mid-create, so no case"},
               {"operation": "CreateIntent", "change": "another principal building the locale (Building)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.2},
               {"operation": "UpdateBot", "change": "another principal building the locale (Building)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.2, "note": "no Lex V2 pair confirmed as a cross-principal EC window"},
           )),
    Family("autoscaling.group", "autoscaling", "AWS::AutoScaling::AutoScalingGroup",
           waiters=(), shapes=("ScalingActivityInProgressFault", "InstanceRefreshInProgressFault",
                               "ResourceContentionFault"),
           notes="the errors are in the SDK; Auto Scaling ships no waiters, so the observing read is manual",
           manual={"observe": [{"operation": "DescribeInstanceRefreshes", "identifier_param": "AutoScalingGroupName",
                                "path": "InstanceRefreshes[0].Status", "settled": "Successful",
                                "terminal": ["Failed", "Cancelled", "RollbackSuccessful", "RollbackFailed"]}],
                   "citation": "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeInstanceRefreshes.html"}),
    Family("sqs.queue", "sqs", "AWS::SQS::Queue",
           waiters=(), shapes=("QueueDeletedRecently",),
           notes="no state to observe: a queue deleted by another principal cannot be recreated under the "
                 "same name for 60 seconds; EC only when the reference wants the queue back under that name",
           manual={"window_s": 60,
                   "citation": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"}),
    Family("ec2.instance", "ec2", "AWS::EC2::Instance",
           waiters=(("InstanceStopped", "InstanceIds"), ("InstanceRunning", "InstanceIds")),
           shapes=(),
           notes="EC2's model declares no errors at all; the refusing code and operations are manual",
           manual={"refusals": {"IncorrectInstanceState": ["ModifyInstanceAttribute", "StartInstances",
                                                          "StopInstances", "RebootInstances", "TerminateInstances"]},
                   "citation": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html"},
           evidence=(
               {"operation": "ModifyInstanceAttribute", "change": "another principal stopping the instance (stopping)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "IncorrectInstanceState", "waited_s": 14.4},
               {"operation": "StartInstances", "change": "another principal stopping the instance (stopping)", "refused": True, "case": "refusal-probe", "date": "2026-09-24", "code": "IncorrectInstanceState", "waited_s": 21.9},
               {"operation": "StopInstances", "change": "another principal starting the instance (pending)", "refused": False, "case": "refusal-probe", "date": "2026-09-24", "waited_s": 0.6},
           )),
)


# -- building from the SDK ------------------------------------------------------------

def _waiter_observation(session: botocore.session.Session, service: str, waiter: str,
                        identifier_param: str) -> Observation:
    config = session.get_waiter_model(service).get_waiter(waiter)
    settled = None
    terminal: list[str] = []
    absent = None
    path = None
    for acceptor in config.acceptors:
        if acceptor.matcher == "error":
            if acceptor.state == "retry":
                absent = acceptor.expected
            continue
        if acceptor.state == "success" and settled is None:
            settled, path = str(acceptor.expected), acceptor.argument
        elif acceptor.state == "failure":
            terminal.append(str(acceptor.expected))
    if settled is None or path is None:
        raise ValueError(f"{service}.{waiter}: no path-matching success acceptor")
    return Observation(operation=config.operation, identifier_param=identifier_param, path=path,
                       settled=settled, terminal=tuple(terminal), absent_error=absent, waiter=waiter,
                       delay_s=config.delay, max_attempts=config.max_attempts)


def _declaring_operations(session: botocore.session.Session, service: str, shape: str) -> tuple[str, ...]:
    model = session.get_service_model(service)
    if shape not in model.shape_names:
        raise ValueError(f"{service}: error shape {shape} is not in the model")
    return tuple(sorted(name for name in model.operation_names
                        if any(e.name == shape for e in model.operation_model(name).error_shapes)))


def build(session: botocore.session.Session | None = None) -> dict[str, Any]:
    """The catalogue document, built from the installed SDK plus the manual parts."""
    import botocore

    session = session or botocore.session.get_session()
    entries: list[Entry] = []
    for family in FAMILIES:
        manual = dict(family.manual or {})
        observations = [_waiter_observation(session, family.service, w, p) for w, p in family.waiters]
        observations += [Observation(**{"source": "manual", **o}) for o in manual.get("observe", [])]
        observations += [Observation(**{"source": "manual", **o}) for o in family.extra_observe]
        refusals = {shape: _declaring_operations(session, family.service, shape) for shape in family.shapes}
        model = session.get_service_model(family.service)
        codes = {shape: model.shape_for(shape).error_code or shape for shape in family.shapes}
        for shape, ops in (manual.get("refusals") or {}).items():
            refusals[shape] = tuple(ops)
            codes[shape] = shape
        entries.append(Entry(
            id=family.id, service=family.service, resource=family.resource,
            source="manual" if family.manual else "sdk",
            observe=tuple(observations), refusals=refusals, codes=codes, aliases=family.aliases,
            window_s=manual.get("window_s"), evidence=family.evidence,
            settle=family.settle, notes=family.notes, citation=manual.get("citation", "")))
    return {"schema_version": SCHEMA_VERSION, "botocore": botocore.__version__,
            "entries": [e.as_dict() for e in entries]}


def write(path: Path = CATALOGUE_PATH) -> Path:
    path.write_text(json.dumps(build(), indent=2, sort_keys=True) + "\n")
    return path


# -- loading and observing ------------------------------------------------------------

def _entry_from_dict(d: Mapping[str, Any]) -> Entry:
    return Entry(id=d["id"], service=d["service"], resource=d["resource"], source=d["source"],
                 observe=tuple(Observation(**{**o, "terminal": tuple(o.get("terminal") or ())})
                               for o in d.get("observe") or []),
                 refusals={k: tuple(v) for k, v in (d.get("refusals") or {}).items()},
                 codes=dict(d.get("codes") or {}), aliases=tuple(d.get("aliases") or ()),
                 window_s=d.get("window_s"), settle=d.get("settle"), notes=d.get("notes", ""),
                 citation=d.get("citation", ""), evidence=tuple(d.get("evidence") or ()))


def load(path: Path = CATALOGUE_PATH) -> dict[str, Entry]:
    document = json.loads(Path(path).read_text())
    return {e["id"]: _entry_from_dict(e) for e in document["entries"]}


def entry(entry_id: str, path: Path = CATALOGUE_PATH) -> Entry:
    try:
        return load(path)[entry_id]
    except KeyError:
        raise KeyError(f"no refusal catalogue entry {entry_id!r}") from None


def observe_state(client, observation: Observation, identifier: str, *, service: str) -> str | None:
    """The resource's current state per one observing read; None when it is gone."""
    from botocore.exceptions import ClientError

    shape = botocore.session.get_session().get_service_model(service).operation_model(observation.operation).input_shape
    member = shape.members[observation.identifier_param]
    value: Any = [identifier] if member.type_name == "list" else identifier
    try:
        response = getattr(client, _snake(observation.operation))(**{observation.identifier_param: value})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if observation.absent_error and code == observation.absent_error:
            return None
        raise
    found = jmespath.search(observation.path, response)
    if isinstance(found, list):
        found = found[0] if found else None
    return None if found is None else str(found)


def _poll(session, ent: Entry, identifier: str, observations: tuple[Observation, ...],
          done: Callable[[list[str | None]], bool], *, timeout_s: float, poll_s: float,
          region: str | None) -> dict[str, Any]:
    client = session.client(ent.service, region_name=region) if region else session.client(ent.service)
    started = time.monotonic()
    reads = 0
    while True:
        states = [observe_state(client, o, identifier, service=ent.service) for o in observations]
        reads += 1
        unsettled = [s for s, o in zip(states, observations) if s is not None and s != o.settled]
        result = {"state": unsettled[0] if unsettled else states[0], "states": states,
                  "waited_s": round(time.monotonic() - started, 3), "observations": reads}
        if done(states):
            return {"fired": True, **result}
        terminal = any(s in o.terminal for s, o in zip(states, observations))
        if terminal or time.monotonic() - started >= timeout_s:
            return {"fired": False, **result}
        time.sleep(poll_s)


def _observations(entry_id: str, catalogue: Path, observation_index: int | None) -> tuple[Entry, tuple[Observation, ...]]:
    ent = entry(entry_id, catalogue)
    if not ent.observe:
        raise ValueError(f"{entry_id} has no observing read (window_s={ent.window_s})")
    chosen = ent.observe if observation_index is None else (ent.observe[observation_index],)
    return ent, chosen


def wait_for_state(session, entry_id: str, identifier: str, *, until: Callable[[str | None], bool],
                   timeout_s: float, poll_s: float = 2.0, observation_index: int = 0,
                   catalogue: Path = CATALOGUE_PATH, region: str | None = None) -> dict[str, Any]:
    """Poll one of the entry's observing reads until ``until(state)`` holds or the timeout passes.

    Returns ``{"fired": bool, "state": str | None, "states": [...], "waited_s": float,
    "observations": n}``. Never raises on timeout: a distractor program reports ``fired: False``
    and lets the held call through, and certification then fails that distractor.
    """
    ent, chosen = _observations(entry_id, catalogue, observation_index)
    return _poll(session, ent, identifier, chosen, lambda states: until(states[0]),
                 timeout_s=timeout_s, poll_s=poll_s, region=region)


def wait_until_busy(session, entry_id: str, identifier: str, *, timeout_s: float = 120.0, poll_s: float = 2.0,
                    observation_index: int | None = None, catalogue: Path = CATALOGUE_PATH,
                    region: str | None = None) -> dict[str, Any]:
    """For distractor programs: return once any of the entry's reads shows the resource not settled."""
    ent, chosen = _observations(entry_id, catalogue, observation_index)
    return _poll(session, ent, identifier, chosen,
                 lambda states: any(s is not None and s != o.settled for s, o in zip(states, chosen)),
                 timeout_s=timeout_s, poll_s=poll_s, region=region)


def wait_until_settled(session, entry_id: str, identifier: str, *, timeout_s: float = 900.0, poll_s: float = 2.0,
                       observation_index: int | None = None, catalogue: Path = CATALOGUE_PATH,
                       region: str | None = None) -> dict[str, Any]:
    """For teardown and certification: return once every read shows the resource settled, or it is gone."""
    ent, chosen = _observations(entry_id, catalogue, observation_index)
    return _poll(session, ent, identifier, chosen,
                 lambda states: all(s is None or s == o.settled for s, o in zip(states, chosen)),
                 timeout_s=timeout_s, poll_s=poll_s, region=region)


def _snake(operation: str) -> str:
    out = []
    for i, ch in enumerate(operation):
        if ch.isupper() and i and (not operation[i - 1].isupper() or (i + 1 < len(operation) and operation[i + 1].islower())):
            out.append("_")
        out.append(ch.lower())
    return "".join(out)
