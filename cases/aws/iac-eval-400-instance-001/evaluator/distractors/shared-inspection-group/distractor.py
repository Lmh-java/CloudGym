from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The platform keeping one inspection pool for the account's gateway traffic.

The account runs one pool for traffic a gateway front hands off for inspection, and every such
front hands its traffic to that pool. The pool takes GENEVE on the port gateway fronts hand off
on, addresses its members as machines, and stands in the inspection network so that network's
fronts can reach it. A front that hands its traffic to a second pool standing beside it is the
thing this exists to prevent: a gateway listener has one default action and that action names
exactly one pool, so the two cannot both be what the front forwards to.

The pool is found by its name, never by a physical id: every deployment mints new ids.

Trigger: the agent's first ``elbv2:DescribeTargetGroups`` — the call is held until the pool
stands — so the first look the agent takes at what pools the region already holds returns this
one. The snapshot fallback is a front
of the agent's going up in the inspection network (an appliance of the agent's running in it, a
pool of the agent's for it, or a load balancer of the agent's standing in one of its segments)
while no pool of this name stands. Neither matches the untouched initial state: at S0 the VPC
runs nothing, has no front of any kind, no target group of any kind exists, and no
DescribeTargetGroups has been made.

Idempotent: it keeps one pool, and re-reads rather than re-creating when the pool already
stands.
"""

VPC_CIDR = "10.70.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "inspection"
POOL_NAME = "inspection-shared-geneve"
POOL_PORT = 6081
# The fronts and pools the account's programs stand up; neither of them is the agent's own.
PROGRAM_POOLS = {POOL_NAME}
PROGRAM_FRONTS = {"inspection-stage-gwlb"}


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _inspection_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _front_going_up(snapshot, vpcs: set) -> bool:
    """A front of the agent's is going up in the inspection network."""
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        props = props or {}
        if props.get("VpcId") in vpcs and props.get("Name") not in PROGRAM_POOLS:
            return True
    segments = {
        (props or {}).get("SubnetId") or identifier
        for identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items()
        if (props or {}).get("VpcId") in vpcs
    }
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::LoadBalancer").values():
        props = props or {}
        if props.get("Name") in PROGRAM_FRONTS:
            continue
        spanned = set(props.get("Subnets") or []) | {
            (mapping or {}).get("SubnetId")
            for mapping in props.get("SubnetMappings") or []
        }
        if segments.intersection(spanned):
            return True
    for props in _resources(snapshot, "AWS::EC2::Instance").values():
        if (props or {}).get("VpcId") in vpcs:
            return True
    return False


def _front_without_pool(snapshot) -> bool:
    """The agent has started building in the inspection network and the kept pool is absent."""
    vpcs = _inspection_vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        if (props or {}).get("Name") == POOL_NAME:
            return False
    return _front_going_up(snapshot, vpcs)


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the account keeps one inspection pool for gateway traffic, and every gateway "
            "front inspecting traffic in this account hands its traffic to that pool rather "
            "than to a second pool standing beside it"),
    api=on_api("elbv2", "DescribeTargetGroups", phase="before"),
    release="after_completed",
    predicate=_front_without_pool,
    resolution=(
        "What the account already keeps for that purpose is what your front hands traffic "
        "to; a second one of your own is not kept."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    elbv2 = boto3.client("elbv2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    from botocore.exceptions import ClientError

    try:
        standing = elbv2.describe_target_groups(Names=[POOL_NAME])["TargetGroups"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "TargetGroupNotFound":
            raise
        standing = []
    if standing:
        arn = standing[0]["TargetGroupArn"]
        return {"pool": POOL_NAME, "arn": arn, "note": "already kept",
                "fingerprint": [POOL_NAME, arn], "trigger": trigger}

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"pool": None, "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    created = elbv2.create_target_group(
        Name=POOL_NAME,
        Protocol="GENEVE",
        Port=POOL_PORT,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        HealthCheckPort="80",
    )["TargetGroups"][0]
    arn = created["TargetGroupArn"]

    return {"pool": POOL_NAME, "arn": arn, "vpc": vpc_id,
            "fingerprint": [POOL_NAME, arn], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
