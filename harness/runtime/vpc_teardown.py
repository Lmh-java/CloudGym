"""Clear what Terraform does not own out of a VPC it is about to destroy.

Agents create things the case never declared (a route table for a CodeBuild
project, a security group, an endpoint) and the extras cleanup only sees the
case's own resource types, so ``terraform destroy`` then retries DeleteVpc
against DependencyViolation until it gives up — while holding the plugin
cache's shared lock, which stalls every other cell's init. This walks the VPC
in dependency order and deletes every unowned resource in it; Terraform's own
resources are left for Terraform, and anything already gone is fine.
"""

from __future__ import annotations

import time
from typing import Callable, Iterable

from botocore.exceptions import ClientError


def _quiet(fn: Callable[[], object]) -> bool:
    try:
        fn()
        return True
    except ClientError:
        return False


def clear_vpc_dependencies(session, vpc_id: str, owned: Iterable[str], *, sleep=time.sleep) -> list[str]:
    """Delete every resource in ``vpc_id`` whose id is not in ``owned``; returns what was removed."""
    owned = set(owned)
    ec2 = session.client("ec2")
    elbv2 = session.client("elbv2")
    flt = [{"Name": "vpc-id", "Values": [vpc_id]}]
    removed: list[str] = []

    def take(label: str, resource_id: str, fn: Callable[[], object]) -> None:
        if resource_id in owned:
            return
        if _quiet(fn):
            removed.append(f"{label}/{resource_id}")

    # 0. load balancers, target groups, instances: their interfaces pin everything below
    for page in elbv2.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancers", []):
            if lb.get("VpcId") != vpc_id:
                continue
            arn = lb["LoadBalancerArn"]

            def kill_lb(a=arn):
                _quiet(lambda: elbv2.modify_load_balancer_attributes(
                    LoadBalancerArn=a, Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}]))
                elbv2.delete_load_balancer(LoadBalancerArn=a)
                elbv2.get_waiter("load_balancers_deleted").wait(
                    LoadBalancerArns=[a], WaiterConfig={"Delay": 10, "MaxAttempts": 40})
            take("elb", arn, kill_lb)
    for page in elbv2.get_paginator("describe_target_groups").paginate():
        for tg in page.get("TargetGroups", []):
            if tg.get("VpcId") == vpc_id:
                take("targetgroup", tg["TargetGroupArn"],
                     lambda a=tg["TargetGroupArn"]: elbv2.delete_target_group(TargetGroupArn=a))
    instances = [i["InstanceId"] for r in ec2.describe_instances(Filters=flt).get("Reservations", [])
                 for i in r.get("Instances", [])
                 if (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down") and i["InstanceId"] not in owned]
    if instances:
        def kill_instances():
            ec2.terminate_instances(InstanceIds=instances)
            ec2.get_waiter("instance_terminated").wait(InstanceIds=instances, WaiterConfig={"Delay": 5, "MaxAttempts": 60})
        if _quiet(kill_instances):
            removed.extend(f"instance/{i}" for i in instances)
    # 1. endpoints, then detached interfaces
    endpoints = [e["VpcEndpointId"] for e in ec2.describe_vpc_endpoints(Filters=flt).get("VpcEndpoints", []) if e["VpcEndpointId"] not in owned]
    if endpoints and _quiet(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=endpoints)):
        removed.extend(f"endpoint/{e}" for e in endpoints)
    for eni in ec2.describe_network_interfaces(Filters=flt).get("NetworkInterfaces", []):
        if eni.get("Status") == "available":
            take("eni", eni["NetworkInterfaceId"],
                 lambda i=eni["NetworkInterfaceId"]: ec2.delete_network_interface(NetworkInterfaceId=i))
    # 2. security groups: revoke every rule first (they cross-reference), then delete the unowned
    groups = [g for g in ec2.describe_security_groups(Filters=flt).get("SecurityGroups", []) if g["GroupName"] != "default"]
    unowned_groups = [g for g in groups if g["GroupId"] not in owned]
    if unowned_groups:
        for g in groups:  # rules in owned groups can reference unowned ones, so revoke everywhere
            if g.get("IpPermissions"):
                _quiet(lambda g=g: ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"]))
            if g.get("IpPermissionsEgress") and g["GroupId"] not in owned:
                _quiet(lambda g=g: ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"]))
    for g in unowned_groups:
        take("sg", g["GroupId"], lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid))
    # 3. subnets, non-main route tables, internet gateways
    for sn in ec2.describe_subnets(Filters=flt).get("Subnets", []):
        take("subnet", sn["SubnetId"], lambda i=sn["SubnetId"]: ec2.delete_subnet(SubnetId=i))
    for rt in ec2.describe_route_tables(Filters=flt).get("RouteTables", []):
        if any(a.get("Main") for a in rt.get("Associations", [])) or rt["RouteTableId"] in owned:
            continue

        def kill_rt(table=rt):
            for a in table.get("Associations", []):
                if a.get("RouteTableAssociationId"):
                    _quiet(lambda a=a: ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"]))
            ec2.delete_route_table(RouteTableId=table["RouteTableId"])
        take("rtb", rt["RouteTableId"], kill_rt)
    for igw in ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]).get("InternetGateways", []):
        def kill_igw(g=igw["InternetGatewayId"]):
            ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=g)
        take("igw", igw["InternetGatewayId"], kill_igw)
    return removed
