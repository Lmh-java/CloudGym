"""Reset the sandbox account to baseline: delete everything a generation/cert run
can leave behind when it is interrupted mid-deploy.

    uv run sandbox-clean --allow-aws            # sweep and delete (primary sandbox)
    uv run sandbox-clean --allow-aws --dry-run  # list what would be deleted
    uv run sandbox-clean --allow-aws --account <id|label>   # one pool account instead

The certifier destroys and leak-checks after every arm, but a run killed *during*
a deploy (laptop sleep, Ctrl-C) leaves a half-built stack terraform never tracked —
most painfully an 8-type VPC stack whose security groups cross-reference each other
and whose subnets are pinned by VPC-endpoint ENIs. Tearing that down by hand takes
several dependency-ordered passes; this does it in one.

Account safety: credentials come from ``sandbox_env()``, which verifies the caller is
the configured sandbox account (the primary, or the named ``[[aws.pool.accounts]]``
member) before returning frozen creds — the same guard every deploy uses. The default VPC, AWS service-linked roles, and AWS-managed
policies are never touched.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

PROTECTED_ROLE_MARKERS = ("AWSServiceRole", "AWSReserved", "OrganizationAccountAccessRole")


def _session(region: str, target=None) -> tuple[boto3.Session, str]:
    from scripts.common import sandbox_env

    env = sandbox_env(region, target)
    creds = env["agent_env"]
    return boto3.Session(
        aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=creds.get("AWS_SESSION_TOKEN"),
        region_name=region,
    ), env["account"]


def resolve_target(selector: str | None):
    """The primary sandbox, or the pool member whose account id, label or profile is ``selector``."""
    from harness.aws_safety import AwsSafetyError, load_aws_target, load_pool_targets

    if not selector:
        return load_aws_target(REPO_ROOT)
    for target in load_pool_targets(REPO_ROOT):
        if selector in (target.account_id, target.label, target.profile):
            return target
    raise AwsSafetyError(f"no sandbox account matches {selector!r} in .cloudgym/aws.local.toml")


def sweep(target, region: str | None = None, *, dry_run: bool) -> "Sweeper":
    """Run the sweeper against one target and return it (``deleted`` / ``failed`` filled in)."""
    region = region or target.region
    session, _account = _session(region, target)
    sweeper = Sweeper(session, region, dry_run=dry_run)
    sweeper.run()
    return sweeper


class Sweeper:
    def __init__(self, session: boto3.Session, region: str, *, dry_run: bool):
        self.s = session
        self.region = region
        self.dry = dry_run
        self.deleted: list[str] = []
        self.failed: list[str] = []
        self.unavailable: list[str] = []   # services the account cannot list yet (new-account subscription lag)

    def _do(self, label: str, fn) -> None:
        if self.dry:
            print(f"  would delete {label}")
            self.deleted.append(label)
            return
        try:
            fn()
            print(f"  deleted {label}")
            self.deleted.append(label)
        except ClientError as e:
            print(f"  FAILED {label}: {e.response.get('Error', {}).get('Code')}")
            self.failed.append(label)

    # -- service resources (leaves first) ------------------------------------

    def codebuild(self) -> None:
        cb = self.s.client("codebuild")
        names: list[str] = []
        for page in cb.get_paginator("list_projects").paginate():
            names.extend(page.get("projects", []))
        for name in names:
            self._do(f"codebuild/{name}", lambda n=name: cb.delete_project(name=n))

    def lambdas(self) -> None:
        lam = self.s.client("lambda")
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                name = fn["FunctionName"]
                self._do(f"lambda/{name}", lambda n=name: lam.delete_function(FunctionName=n))

    def eventbridge(self) -> None:
        ev = self.s.client("events")
        for page in ev.get_paginator("list_rules").paginate():
            for rule in page.get("Rules", []):
                if rule.get("ManagedBy"):
                    continue
                name = rule["Name"]

                def kill(n=name):
                    ids = [t["Id"] for t in ev.list_targets_by_rule(Rule=n).get("Targets", [])]
                    if ids:
                        ev.remove_targets(Rule=n, Ids=ids, Force=True)
                    ev.delete_rule(Name=n, Force=True)
                self._do(f"events-rule/{name}", kill)

    def logs(self) -> None:
        """Every log group and resource policy: cases create them with fixed names, and a
        stale one makes the next deploy of the same case fail with AlreadyExists."""
        logs = self.s.client("logs")
        for page in logs.get_paginator("describe_log_groups").paginate():
            for group in page.get("logGroups", []):
                name = group["logGroupName"]
                self._do(f"log-group/{name}", lambda n=name: logs.delete_log_group(logGroupName=n))
        for policy in logs.describe_resource_policies().get("resourcePolicies", []):
            name = policy["policyName"]
            self._do(f"logs-resource-policy/{name}", lambda n=name: logs.delete_resource_policy(policyName=n))

    def route53_query_logs(self) -> None:
        """Query logging configs first: they are not deleted with their zone, and an orphan
        pointing at a deleted zone is exactly what accumulates between runs."""
        r53 = self.s.client("route53")
        for page in r53.get_paginator("list_query_logging_configs").paginate():
            for config in page.get("QueryLoggingConfigs", []):
                cid = config["Id"]
                self._do(f"route53-query-log/{cid} (zone {config.get('HostedZoneId')})",
                         lambda c=cid: r53.delete_query_logging_config(Id=c))

    def route53(self) -> None:
        r53 = self.s.client("route53")
        for page in r53.get_paginator("list_hosted_zones").paginate():
            for zone in page.get("HostedZones", []):
                zone_id = zone["Id"].split("/")[-1]

                def kill(zid=zone_id, zname=zone["Name"]):
                    records = [r for pg in r53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zid)
                               for r in pg["ResourceRecordSets"]
                               if not (r["Type"] in ("NS", "SOA") and r["Name"] == zname)]
                    for start in range(0, len(records), 100):
                        r53.change_resource_record_sets(HostedZoneId=zid, ChangeBatch={
                            "Changes": [{"Action": "DELETE", "ResourceRecordSet": r} for r in records[start:start + 100]]})
                    r53.delete_hosted_zone(Id=zid)
                self._do(f"hosted-zone/{zone['Name']}", kill)
        for page in r53.get_paginator("list_health_checks").paginate():
            for check in page.get("HealthChecks", []):
                self._do(f"health-check/{check['Id']}", lambda i=check["Id"]: r53.delete_health_check(HealthCheckId=i))

    def rds(self) -> None:
        rds = self.s.client("rds")
        instances = [i for page in rds.get_paginator("describe_db_instances").paginate() for i in page["DBInstances"]]
        for inst in instances:
            name = inst["DBInstanceIdentifier"]

            def kill(n=name):
                try:
                    rds.modify_db_instance(DBInstanceIdentifier=n, DeletionProtection=False, ApplyImmediately=True)
                except ClientError:
                    pass
                rds.delete_db_instance(DBInstanceIdentifier=n, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
                rds.get_waiter("db_instance_deleted").wait(
                    DBInstanceIdentifier=n, WaiterConfig={"Delay": 15, "MaxAttempts": 80})
            self._do(f"rds-instance/{name}", kill)
        for page in rds.get_paginator("describe_db_subnet_groups").paginate():
            for group in page.get("DBSubnetGroups", []):
                name = group["DBSubnetGroupName"]
                self._do(f"db-subnet-group/{name}", lambda n=name: rds.delete_db_subnet_group(DBSubnetGroupName=n))
        for page in rds.get_paginator("describe_db_parameter_groups").paginate():
            for group in page.get("DBParameterGroups", []):
                name = group["DBParameterGroupName"]
                if name.startswith("default."):
                    continue
                self._do(f"db-parameter-group/{name}", lambda n=name: rds.delete_db_parameter_group(DBParameterGroupName=n))

    def elasticbeanstalk(self) -> None:
        eb = self.s.client("elasticbeanstalk")
        for app in eb.describe_applications().get("Applications", []):
            name = app["ApplicationName"]

            def kill(n=name):
                eb.delete_application(ApplicationName=n, TerminateEnvByForce=True)
                deadline = time.monotonic() + 20 * 60
                while time.monotonic() < deadline:
                    envs = eb.describe_environments(ApplicationName=n, IncludeDeleted=False).get("Environments", [])
                    if all(e["Status"] == "Terminated" for e in envs):
                        return
                    time.sleep(15)
            self._do(f"beanstalk-application/{name}", kill)

    def dynamodb(self) -> None:
        ddb = self.s.client("dynamodb")
        for name in ddb.list_tables().get("TableNames", []):
            def kill(n=name):
                # An execution-conflict run can leave a table with an index still building
                # (a distractor's change in flight); DeleteTable and UpdateTable then refuse with
                # ResourceInUseException. Wait until the table and every index are settled —
                # the refusal the EC cases stage, met by the sweep itself (2026-09-22).
                from harness.runtime.case import _dynamodb_settled

                _dynamodb_settled(ddb, n, timeout_s=1200.0, poll_s=10.0)
                # A case may ask for a protected table, and DeleteTable then fails with a
                # ValidationException — the way a protected load balancer refuses to go.
                try:
                    ddb.update_table(TableName=n, DeletionProtectionEnabled=False)
                    ddb.get_waiter("table_exists").wait(
                        TableName=n, WaiterConfig={"Delay": 3, "MaxAttempts": 40})
                except ClientError:
                    pass
                ddb.delete_table(TableName=n)
                # DeleteTable is asynchronous (the table sits in DELETING for a while); the
                # baseline proof that follows the sweep must not see it, so wait it out.
                ddb.get_waiter("table_not_exists").wait(TableName=n, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            self._do(f"dynamodb/{name}", kill)

    def firehose(self) -> None:
        fh = self.s.client("firehose")
        names: list[str] = []
        start = None
        while True:
            page = fh.list_delivery_streams(Limit=100, **({"ExclusiveStartDeliveryStreamName": start} if start else {}))
            names.extend(page.get("DeliveryStreamNames", []))
            if not page.get("HasMoreDeliveryStreams") or not names:
                break
            start = names[-1]
        for name in names:
            def kill(n=name):
                # A stream mid-encryption change refuses the delete (ResourceInUseException);
                # force-delete still needs it settled, so wait for the catalogue's reads first.
                from harness.runtime.refusals import wait_until_settled
                try:
                    wait_until_settled(self.s, "firehose.delivery-stream", n, timeout_s=600.0, poll_s=10.0)
                except Exception:  # noqa: BLE001 - try the delete anyway
                    pass
                fh.delete_delivery_stream(DeliveryStreamName=n, AllowForceDelete=True)
            self._do(f"firehose/{name}", kill)

    def apigateway(self) -> None:
        apigw = self.s.client("apigateway")
        for page in apigw.get_paginator("get_rest_apis").paginate():
            for api in page.get("items", []):
                def kill(a=api["id"]):
                    # DeleteRestApi is throttled to about one call per 30 s per account.
                    for attempt in range(6):
                        try:
                            apigw.delete_rest_api(restApiId=a)
                            return
                        except ClientError as exc:
                            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or attempt == 5:
                                raise
                            time.sleep(35)
                self._do(f"apigateway/{api.get('name')}({api['id']})", kill)

    def sqs(self) -> None:
        sqs = self.s.client("sqs")
        for page in sqs.get_paginator("list_queues").paginate():
            for url in page.get("QueueUrls", []) or []:
                self._do(f"sqs/{url.rsplit('/', 1)[-1]}", lambda u=url: sqs.delete_queue(QueueUrl=u))

    def placement_groups(self) -> None:
        # After the VPC step, which terminates the instances that sit in a group.
        ec2 = self.s.client("ec2")
        for group in ec2.describe_placement_groups().get("PlacementGroups", []):
            name = group["GroupName"]

            def kill(n=name):
                for attempt in range(12):       # terminating instances release the group slowly
                    try:
                        ec2.delete_placement_group(GroupName=n)
                        return
                    except ClientError as exc:
                        if exc.response.get("Error", {}).get("Code") != "InvalidPlacementGroup.InUse" or attempt == 11:
                            raise
                        time.sleep(15)
            self._do(f"placement-group/{name}", kill)

    def lambda_mappings(self) -> None:
        lam = self.s.client("lambda")
        for page in lam.get_paginator("list_event_source_mappings").paginate():
            for m in page.get("EventSourceMappings", []):
                self._do(f"lambda-esm/{m['UUID']}", lambda u=m["UUID"]: lam.delete_event_source_mapping(UUID=u))

    def efs(self) -> None:
        # Before the VPC step: a mount target's network interface holds its subnet.
        from harness.runtime.case import delete_resource
        efs = self.s.client("efs")
        for page in efs.get_paginator("describe_file_systems").paginate():
            for fs in page.get("FileSystems", []):
                fid = fs["FileSystemId"]
                self._do(f"efs/{fid}", lambda f=fid: delete_resource(self.s, "AWS::EFS::FileSystem", f))

    def lightsail(self) -> None:
        ls = self.s.client("lightsail")
        for inst in ls.get_instances().get("instances", []):
            self._do(f"lightsail-instance/{inst['name']}",
                     lambda n=inst["name"]: ls.delete_instance(instanceName=n, forceDeleteAddOns=True))
        for disk in ls.get_disks().get("disks", []):
            def kill(n=disk["name"]):
                for attempt in range(12):           # a disk frees once its instance is gone
                    try:
                        ls.delete_disk(diskName=n, forceDeleteAddOns=True)
                        return
                    except ClientError:
                        if attempt == 11:
                            raise
                        time.sleep(10)
            self._do(f"lightsail-disk/{disk['name']}", kill)

    def flink(self) -> None:
        ka = self.s.client("kinesisanalyticsv2")
        for app in ka.list_applications().get("ApplicationSummaries", []):
            name = app["ApplicationName"]

            def kill(n=name):
                created = ka.describe_application(ApplicationName=n)["ApplicationDetail"]["CreateTimestamp"]
                ka.delete_application(ApplicationName=n, CreateTimestamp=created)
            self._do(f"flink/{name}", kill)

    def lex(self) -> None:
        lex = self.s.client("lexv2-models")
        for bot in lex.list_bots().get("botSummaries", []):
            self._do(f"lex-bot/{bot['botName']}",
                     lambda b=bot["botId"]: lex.delete_bot(botId=b, skipResourceInUseCheck=True))

    def backup(self) -> None:
        bk = self.s.client("backup")
        for plan in bk.list_backup_plans().get("BackupPlansList", []):
            pid = plan["BackupPlanId"]
            for sel in bk.list_backup_selections(BackupPlanId=pid).get("BackupSelectionsList", []):
                self._do(f"backup-selection/{sel['SelectionId']}",
                         lambda p=pid, s=sel["SelectionId"]: bk.delete_backup_selection(BackupPlanId=p, SelectionId=s))
            self._do(f"backup-plan/{plan['BackupPlanName']}", lambda p=pid: bk.delete_backup_plan(BackupPlanId=p))
        for vault in bk.list_backup_vaults().get("BackupVaultList", []):
            name = vault["BackupVaultName"]
            if name in ("Default",) or name.startswith("aws/"):
                continue

            def kill(n=name):
                for rp in bk.list_recovery_points_by_backup_vault(BackupVaultName=n).get("RecoveryPoints", []):
                    bk.delete_recovery_point(BackupVaultName=n, RecoveryPointArn=rp["RecoveryPointArn"])
                bk.delete_backup_vault(BackupVaultName=n)
            self._do(f"backup-vault/{name}", kill)

    def addresses(self) -> None:
        # After the VPC step: instances and load balancers have let go of their addresses.
        ec2 = self.s.client("ec2")
        for addr in ec2.describe_addresses().get("Addresses", []):
            def kill(a=addr):
                if a.get("AssociationId"):
                    ec2.disassociate_address(AssociationId=a["AssociationId"])
                ec2.release_address(AllocationId=a["AllocationId"])
            self._do(f"eip/{addr.get('PublicIp')}", kill)

    def sns(self) -> None:
        sns = self.s.client("sns")
        for page in sns.get_paginator("list_topics").paginate():
            for topic in page.get("Topics", []):
                arn = topic["TopicArn"]
                self._do(f"sns/{arn.rsplit(':', 1)[-1]}", lambda a=arn: sns.delete_topic(TopicArn=a))

    def cloudwatch(self) -> None:
        cw = self.s.client("cloudwatch")
        names: list[str] = []
        for page in cw.get_paginator("describe_alarms").paginate():
            names += [a["AlarmName"] for a in page.get("MetricAlarms", [])]
            names += [a["AlarmName"] for a in page.get("CompositeAlarms", [])]
        if names:
            self._do(f"cw-alarms({len(names)})", lambda: cw.delete_alarms(AlarmNames=names))

    def buckets(self) -> None:
        s3 = self.s.resource("s3")
        client = self.s.client("s3")
        for b in client.list_buckets().get("Buckets", []):
            name = b["Name"]
            # a bucket's region: LocationConstraint None == us-east-1
            try:
                loc = client.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            except ClientError:
                loc = self.region
            if loc != self.region:
                continue

            def kill(n=name):
                # An agent asked to protect a bucket may leave a policy that denies
                # s3:DeleteBucket; without dropping it first the bucket is unremovable.
                try:
                    client.delete_bucket_policy(Bucket=n)
                except ClientError:
                    pass
                bucket = s3.Bucket(n)
                bucket.object_versions.delete()
                bucket.objects.all().delete()
                bucket.delete()
            self._do(f"s3/{name}", kill)

    # -- VPCs: the hard one, full dependency-ordered teardown ----------------

    def _teardown_elbv2(self, vpc: str) -> None:
        """Load balancers and target groups in ``vpc``; deletion protection cleared first.

        A case may ask for a protected load balancer (IaC-Eval row 390 does), and
        DeleteLoadBalancer then fails with OperationNotPermitted — leaving the ENIs that
        keep every subnet and security group in the VPC undeletable.
        """
        elbv2 = self.s.client("elbv2")
        balancers = [lb for page in elbv2.get_paginator("describe_load_balancers").paginate()
                     for lb in page.get("LoadBalancers", []) if lb.get("VpcId") == vpc]
        for balancer in balancers:
            def kill(arn=balancer["LoadBalancerArn"]):
                elbv2.modify_load_balancer_attributes(
                    LoadBalancerArn=arn,
                    Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}])
                elbv2.delete_load_balancer(LoadBalancerArn=arn)
                elbv2.get_waiter("load_balancers_deleted").wait(
                    LoadBalancerArns=[arn], WaiterConfig={"Delay": 10, "MaxAttempts": 40})
            self._do(f"elb/{balancer['LoadBalancerName']}", kill)
        groups = [tg for page in elbv2.get_paginator("describe_target_groups").paginate()
                  for tg in page.get("TargetGroups", []) if tg.get("VpcId") == vpc]
        for group in groups:
            self._do(f"targetgroup/{group['TargetGroupName']}",
                     lambda arn=group["TargetGroupArn"]: elbv2.delete_target_group(TargetGroupArn=arn))

    def _terminate_instances(self, ec2, vpc: str) -> None:
        instances = [i["InstanceId"]
                     for reservation in ec2.describe_instances(
                         Filters=[{"Name": "vpc-id", "Values": [vpc]}]).get("Reservations", [])
                     for i in reservation.get("Instances", [])
                     if (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down")]
        if not instances:
            return

        def kill():
            ec2.terminate_instances(InstanceIds=instances)
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=instances, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
        self._do(f"instances/{','.join(instances)}", kill)

    def vpcs(self) -> None:
        ec2 = self.s.client("ec2")
        vpcs = [v["VpcId"] for v in ec2.describe_vpcs().get("Vpcs", []) if not v.get("IsDefault")]
        for vpc in vpcs:
            self._teardown_vpc(ec2, vpc)

    def _teardown_vpc(self, ec2, vpc: str) -> None:
        print(f"  vpc {vpc}: dependency teardown")
        flt = [{"Name": "vpc-id", "Values": [vpc]}]
        # 0. load balancers and instances: their ENIs pin subnets and security groups,
        #    and neither is detachable while the owner lives
        self._teardown_elbv2(vpc)
        self._terminate_instances(ec2, vpc)
        # 1. VPC endpoints (their ENIs pin subnets/SGs)
        eps = [e["VpcEndpointId"] for e in ec2.describe_vpc_endpoints(Filters=flt).get("VpcEndpoints", [])]
        if eps and not self.dry:
            ec2.delete_vpc_endpoints(VpcEndpointIds=eps)
        # 2. detach + delete leftover ENIs
        if not self.dry:
            for eni in ec2.describe_network_interfaces(Filters=flt).get("NetworkInterfaces", []):
                att = (eni.get("Attachment") or {}).get("AttachmentId")
                if att:
                    try:
                        ec2.detach_network_interface(AttachmentId=att, Force=True)
                    except ClientError:
                        pass
            time.sleep(6)
            for eni in ec2.describe_network_interfaces(Filters=flt).get("NetworkInterfaces", []):
                try:
                    ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                except ClientError:
                    pass
        # 2b. peering connections that touch this VPC
        for side in ("requester-vpc-info.vpc-id", "accepter-vpc-info.vpc-id"):
            for pcx in ec2.describe_vpc_peering_connections(
                    Filters=[{"Name": side, "Values": [vpc]}]).get("VpcPeeringConnections", []):
                if (pcx.get("Status") or {}).get("Code") in ("deleted", "rejected", "failed", "expired"):
                    continue
                self._do(f"pcx/{pcx['VpcPeeringConnectionId']}",
                         lambda i=pcx["VpcPeeringConnectionId"]: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=i))
        # 3. security groups — revoke every rule first (they cross-reference), then delete
        groups = ec2.describe_security_groups(Filters=flt).get("SecurityGroups", [])
        sgs = [g for g in groups if g["GroupName"] != "default"]
        if not self.dry:
            # The default group can hold a rule naming another group (an agent allowed its NLB's
            # group in): that group then never deletes (DependencyViolation; sbx-02, 2026-09-24).
            # Only rules naming *other* groups go; the default group's own self-rule stays.
            for g in groups:
                if g["GroupName"] != "default":
                    continue
                for field, revoke in (("IpPermissions", ec2.revoke_security_group_ingress),
                                      ("IpPermissionsEgress", ec2.revoke_security_group_egress)):
                    foreign = [p for p in g.get(field) or []
                               if any(pair.get("GroupId") not in (None, g["GroupId"]) for pair in p.get("UserIdGroupPairs") or [])]
                    if foreign:
                        try:
                            revoke(GroupId=g["GroupId"], IpPermissions=foreign)
                        except ClientError:
                            pass
            for g in sgs:
                if g.get("IpPermissions"):
                    try:
                        ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
                    except ClientError:
                        pass
                if g.get("IpPermissionsEgress"):
                    try:
                        ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
                    except ClientError:
                        pass
        for g in sgs:
            self._do(f"sg/{g['GroupId']}", lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid))
        # 4. subnets
        for sn in ec2.describe_subnets(Filters=flt).get("Subnets", []):
            self._do(f"subnet/{sn['SubnetId']}", lambda i=sn["SubnetId"]: ec2.delete_subnet(SubnetId=i))
        # 4b. non-default network ACLs (their subnets are gone now, so nothing holds them)
        for acl in ec2.describe_network_acls(Filters=flt).get("NetworkAcls", []):
            if acl.get("IsDefault"):
                continue
            self._do(f"acl/{acl['NetworkAclId']}", lambda i=acl["NetworkAclId"]: ec2.delete_network_acl(NetworkAclId=i))
        # 5. non-main route tables
        for rt in ec2.describe_route_tables(Filters=flt).get("RouteTables", []):
            if any(a.get("Main") for a in rt.get("Associations", [])):
                continue
            for a in rt.get("Associations", []):
                if a.get("RouteTableAssociationId") and not self.dry:
                    try:
                        ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])
                    except ClientError:
                        pass
            self._do(f"rtb/{rt['RouteTableId']}", lambda i=rt["RouteTableId"]: ec2.delete_route_table(RouteTableId=i))
        # 6. internet gateways
        for igw in ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc]}]).get("InternetGateways", []):
            gid = igw["InternetGatewayId"]

            def kill(g=gid):
                ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=vpc)
                ec2.delete_internet_gateway(InternetGatewayId=g)
            self._do(f"igw/{gid}", kill)
        # 7. the VPC itself
        self._do(f"vpc/{vpc}", lambda: ec2.delete_vpc(VpcId=vpc))

    # -- IAM (after everything that could reference a role/policy) ------------

    def iam(self) -> None:
        iam = self.s.client("iam")
        for page in iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                name = role["RoleName"]
                if any(m in name for m in PROTECTED_ROLE_MARKERS) or role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                def kill(n=name):
                    for p in iam.list_attached_role_policies(RoleName=n).get("AttachedPolicies", []):
                        iam.detach_role_policy(RoleName=n, PolicyArn=p["PolicyArn"])
                    for pn in iam.list_role_policies(RoleName=n).get("PolicyNames", []):
                        iam.delete_role_policy(RoleName=n, PolicyName=pn)
                    for ip in iam.list_instance_profiles_for_role(RoleName=n).get("InstanceProfiles", []):
                        iam.remove_role_from_instance_profile(
                            InstanceProfileName=ip["InstanceProfileName"], RoleName=n)
                    iam.delete_role(RoleName=n)
                self._do(f"iam-role/{name}", kill)
        for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
            for pol in page.get("Policies", []):
                arn = pol["Arn"]

                def kill(a=arn):
                    ent = iam.list_entities_for_policy(PolicyArn=a)
                    for r in ent.get("PolicyRoles", []):
                        iam.detach_role_policy(RoleName=r["RoleName"], PolicyArn=a)
                    for u in ent.get("PolicyUsers", []):
                        iam.detach_user_policy(UserName=u["UserName"], PolicyArn=a)
                    for g in ent.get("PolicyGroups", []):
                        iam.detach_group_policy(GroupName=g["GroupName"], PolicyArn=a)
                    for v in iam.list_policy_versions(PolicyArn=a).get("Versions", []):
                        if not v["IsDefaultVersion"]:
                            iam.delete_policy_version(PolicyArn=a, VersionId=v["VersionId"])
                    iam.delete_policy(PolicyArn=a)
                self._do(f"iam-policy/{pol['PolicyName']}", kill)

    def run(self) -> None:
        # Leaves before roots: compute/service resources, then VPC network, then IAM.
        # A freshly created account is not subscribed to every service for a while
        # ("Subscription to CodeBuild ... required"); such a service is recorded as
        # unavailable rather than aborting the sweep, so the caller can retry later.
        for step in (self.codebuild, self.apigateway, self.lambda_mappings, self.lambdas, self.eventbridge, self.firehose,
                     self.flink, self.lex, self.lightsail, self.backup, self.efs, self.dynamodb, self.sqs, self.sns,
                     self.cloudwatch, self.logs, self.route53_query_logs, self.route53, self.buckets,
                     self.elasticbeanstalk, self.rds, self.vpcs, self.placement_groups, self.addresses, self.iam):
            try:
                step()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                message = str(exc)
                # A service the SCP does not (yet) allowlist answers with an explicit deny: there
                # is nothing of it to sweep, so it counts as unavailable rather than a failure.
                if code in ("SubscriptionRequiredException", "OptInRequired") or "Subscription to" in message \
                        or "Payer ID" in message or "not allowed access to service" in message \
                        or "explicit deny in a service control policy" in message:
                    self.unavailable.append(f"{step.__name__}: {message[:160]}")
                    print(f"  {step.__name__}: service not available in this account yet", file=sys.stderr)
                    continue
                raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--region", default=None)
    ap.add_argument("--allow-aws", action="store_true", help="required: this deletes real resources")
    ap.add_argument("--dry-run", action="store_true", help="list what would be deleted, delete nothing")
    ap.add_argument("--account", help="pool account id, label or profile (default: the primary sandbox)")
    args = ap.parse_args(argv)
    if not args.allow_aws:
        ap.error("this deletes real resources; pass --allow-aws")

    from harness.aws_safety import AwsSafetyError
    try:
        target = resolve_target(args.account)
    except AwsSafetyError as exc:
        ap.error(str(exc))
    region = args.region or target.region
    session, account = _session(region, target)
    print(f"sandbox-clean: account {account}, region {region}{' (DRY RUN)' if args.dry_run else ''}")
    sweeper = Sweeper(session, region, dry_run=args.dry_run)
    sweeper.run()
    print(f"\n{'would delete' if args.dry_run else 'deleted'} {len(sweeper.deleted)} resource(s); "
          f"{len(sweeper.failed)} failed")
    if sweeper.failed:
        print("failed (rerun — some deps clear on a second pass):")
        for f in sweeper.failed:
            print(f"  {f}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
