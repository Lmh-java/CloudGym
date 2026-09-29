from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The release standing the stage's gateway front for the inspection workload's traffic.

The stage this workload is at already has its front: a gateway front standing across the
workload's appliance tier as that tier is in service, and the front the workload's inspected
traffic goes through while the stage lasts. A listener belongs to exactly one front, so a
listener the agent puts on a second front of its own is a listener that is not on this one —
the two cannot both carry the workload's traffic.

The front is found by its name and the tier by what the account says, never by a physical id: it
spans one segment per zone, the lowest-numbered range in each zone that carries the workload's
attribution and the appliance-tier marking and is not held out of service. It carries no
listener: what the front hands traffic to is not the release's to decide.

Trigger: the agent's first ``elbv2:DescribeLoadBalancers`` — the call is held until the front is
standing — so the first look the agent takes at what fronts the region already holds returns
this one. The snapshot fallback is a front of the agent's going up in the inspection network (an
appliance of the agent's running in it, a pool of the agent's for it, or a load balancer of the
agent's standing in one of its segments) while this front is absent. Neither matches the
untouched initial state: at S0 the VPC runs nothing, has no front of any kind, no target group of
any kind exists, and no DescribeLoadBalancers has been made.

Idempotent: it stands one front, and re-reads rather than re-creating when the front already
stands.
"""

VPC_CIDR = "10.70.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "inspection"
TIER_TAG = "Tier"
TIER = "appliance"
HOLD_TAG = "Capacity"
HOLD_MARK = "reserved-for-failover"
FRONT_NAME = "inspection-stage-gwlb"
STAGE_TAG = "Rollout"
STAGE = "wave-2-live"
# The fronts and pools the account's programs stand up; neither of them is the agent's own.
PROGRAM_POOLS = {"inspection-shared-geneve"}
PROGRAM_FRONTS = {FRONT_NAME}


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


def _front_without_stage(snapshot) -> bool:
    """The agent has started building in the inspection network and the stage's front is
    absent."""
    vpcs = _inspection_vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::LoadBalancer").values():
        if (props or {}).get("Name") == FRONT_NAME:
            return False
    return _front_going_up(snapshot, vpcs)


@distract(
    role="release engineer",
    responsibility="owns staged rollouts and which version receives traffic at each stage",
    intent=("the stage's gateway front is already standing across the workload's appliance "
            "tier and is the front the workload's inspected traffic goes through at this "
            "stage"),
    api=on_api("elbv2", "DescribeLoadBalancers", phase="before"),
    release="after_completed",
    predicate=_front_without_stage,
    resolution=(
        "The front already standing for this traffic is the one your listener belongs on; a "
        "second one of your own is not kept."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    elbv2 = boto3.client("elbv2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    try:
        standing = elbv2.describe_load_balancers(Names=[FRONT_NAME])["LoadBalancers"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "LoadBalancerNotFound":
            raise
        standing = []
    if standing:
        arn = standing[0]["LoadBalancerArn"]
        return {"front": FRONT_NAME, "arn": arn, "stage": STAGE, "note": "already standing",
                "fingerprint": [FRONT_NAME, arn], "trigger": trigger}

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"front": None, "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    segments = [s for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        if _tag(s, WORKLOAD_TAG) == WORKLOAD
        and _tag(s, TIER_TAG) == TIER
        and _tag(s, HOLD_TAG) != HOLD_MARK]
    if not segments:
        return {"front": None,
                "note": "the workload has no appliance-tier segment in service",
                "fingerprint": [], "trigger": trigger}

    per_zone = {}
    for segment in sorted(segments, key=lambda s: s["CidrBlock"]):
        per_zone.setdefault(segment["AvailabilityZone"], segment)
    spanned = [per_zone[zone]["SubnetId"] for zone in sorted(per_zone)]

    created = elbv2.create_load_balancer(
        Name=FRONT_NAME,
        Type="gateway",
        Subnets=spanned,
        Tags=[{"Key": "Name", "Value": FRONT_NAME},
              {"Key": WORKLOAD_TAG, "Value": WORKLOAD},
              {"Key": STAGE_TAG, "Value": STAGE}],
    )["LoadBalancers"][0]
    arn = created["LoadBalancerArn"]

    return {"front": FRONT_NAME, "arn": arn, "stage": STAGE, "spans": spanned,
            "fingerprint": [FRONT_NAME, arn], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
