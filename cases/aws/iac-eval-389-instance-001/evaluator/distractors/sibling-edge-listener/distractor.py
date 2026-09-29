from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The sibling application taking port 80 of the edge balancer it shares.

The sibling team's web application answers on the account's edge balancer in the orders
network, forwarding to its own group ``sibling-web-q8``. A balancer admits exactly one listener
per port, so the sibling answering on 80 and the orders service answering on 80 cannot both
stand: whichever holds that listener's default action is what the balancer serves.

Trigger: the agent's first ``elbv2:CreateListener`` — the call is held until port 80 is taken,
so the workload's own listener meets a port that is already answering — with a snapshot
fallback for a balancer standing in the orders edge subnets while no group of the sibling's
name exists. Neither matches the untouched initial state: at S0 the account holds no load
balancer, no listener and no target group at all.

Idempotent: it finds the balancer by the network it stands in — the one running the
workload's server, since an account can hold a second stack under the same tags — rather
than by a physical id,
reuses its group when it already stands, and re-points the port-80 listener only when that
listener is not already forwarding to it.
"""

VPC_CIDR = "10.40.0.0/16"
WORKLOAD = "orders"
SIBLING_GROUP = "sibling-web-q8"
SIBLING_TAG = "Neighbour"
SIBLING_MARK = "sibling-web"


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _server_vpcs(snapshot) -> set:
    """The networks that actually run one of the workload's servers.

    An account can hold more than one VPC on this range under this attribution — a stack a
    previous run left behind, or one being torn down while this one deploys. The live one is
    the one with a server in it, so every read below is scoped to that rather than to the tags
    alone.
    """
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::Instance").items():
        props = props or {}
        if _tag(props, "Workload") != WORKLOAD:
            continue
        if ((props.get("State") or {}).get("Name") or "running") in ("terminated", "shutting-down"):
            continue
        if props.get("VpcId"):
            found.add(props["VpcId"])
    return found


def _vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR or _tag(props, "Workload") != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    servers = _server_vpcs(snapshot)
    return {vpc for vpc in found if vpc in servers}


def _port_free(snapshot) -> bool:
    """A balancer stands in the orders edge subnets and the sibling is not on it yet."""
    vpcs = _vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        if (props or {}).get("Name") == SIBLING_GROUP and (props or {}).get("VpcId") in vpcs:
            return False
    subnets = {(props or {}).get("SubnetId") or identifier
               for identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items()
               if (props or {}).get("VpcId") in vpcs}
    return any(set((props or {}).get("Subnets") or []) & subnets
               for props in _resources(
                   snapshot, "AWS::ElasticLoadBalancingV2::LoadBalancer").values())


def _pick_vpc(ec2) -> str | None:
    """The network to act on: the one on this range, under this attribution, running a server."""
    vpcs = [v["VpcId"] for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:Workload", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return None
    running = set()
    pages = ec2.get_paginator("describe_instances").paginate(Filters=[
        {"Name": "tag:Workload", "Values": [WORKLOAD]},
        {"Name": "instance-state-name", "Values": ["pending", "running"]}])
    for page in pages:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance.get("VpcId") in vpcs:
                    running.add(instance["VpcId"])
    return sorted(running)[0] if running else sorted(vpcs)[0]


@distract(
    role="developer on a sibling application team",
    responsibility=("owns a second application in the same account that shares the network "
                    "and naming space"),
    intent=("the sibling web application answers on port 80 of the edge balancer standing in "
            "the orders network: that balancer has an HTTP listener on 80 whose default "
            "action forwards to the sibling's own group sibling-web-q8"),
    api=on_api("elbv2", "CreateListener", phase="before"),
    release="after_completed",
    predicate=_port_free,
    resolution=(
        "What I put on your edge is not yours to serve; an edge answers for its own servers, "
        "and there is room for only one answer."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    elbv2 = boto3.client("elbv2", region_name=region)

    vpc_id = _pick_vpc(ec2)
    if vpc_id is None:
        return {"group": None, "listener": None, "note": f"no VPC on {VPC_CIDR}",
                "fingerprint": [], "trigger": trigger}

    balancers = [lb for page in elbv2.get_paginator("describe_load_balancers").paginate()
                 for lb in page["LoadBalancers"]
                 if lb.get("VpcId") == vpc_id and lb.get("Type") == "application"]
    if not balancers:
        return {"group": None, "listener": None, "note": "no balancer stands in that network",
                "fingerprint": [], "trigger": trigger}
    balancer = sorted(balancers, key=lambda lb: lb["LoadBalancerArn"])[0]

    try:
        groups = elbv2.describe_target_groups(Names=[SIBLING_GROUP])["TargetGroups"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "TargetGroupNotFound":
            raise
        groups = []
    group = next((g for g in groups if g.get("VpcId") == vpc_id), None)
    if group is None:
        group = elbv2.create_target_group(
            Name=SIBLING_GROUP, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
            HealthCheckProtocol="HTTP", HealthCheckPath="/",
            Tags=[{"Key": SIBLING_TAG, "Value": SIBLING_MARK}],
        )["TargetGroups"][0]
    arn = group["TargetGroupArn"]
    fingerprint = [SIBLING_GROUP]

    forward = [{"Type": "forward", "TargetGroupArn": arn}]
    listeners = elbv2.describe_listeners(
        LoadBalancerArn=balancer["LoadBalancerArn"])["Listeners"]
    on_eighty = next((listener for listener in listeners if listener.get("Port") == 80), None)
    if on_eighty is None:
        created = elbv2.create_listener(
            LoadBalancerArn=balancer["LoadBalancerArn"], Protocol="HTTP", Port=80,
            DefaultActions=forward)["Listeners"][0]
        return {"group": arn, "name": SIBLING_GROUP, "listener": created["ListenerArn"],
                "took": "created", "fingerprint": fingerprint, "trigger": trigger}

    already = any(action.get("TargetGroupArn") == arn
                  for action in on_eighty.get("DefaultActions") or [])
    if not already:
        elbv2.modify_listener(ListenerArn=on_eighty["ListenerArn"], DefaultActions=forward)
    return {"group": arn, "name": SIBLING_GROUP, "listener": on_eighty["ListenerArn"],
            "took": "already" if already else "repointed",
            "fingerprint": fingerprint, "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
