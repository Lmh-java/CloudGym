from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Reliability keeping the appliance tier's headroom in a segment of its own.

The tier's lowest segment is taken out of service as the headroom the workload must leave
itself: the hold and the reference it is held under go on the segment, and a replacement segment
is cut in the same zone so the tier still covers that zone. The segment stays the workload's and
keeps its tier marking — it is the tier's own reserve, not somebody else's space — but nothing
stands in it and no front reaches into it while the hold stands. A gateway front takes at most
one segment per zone, so in that zone it stands either in the held segment or in the replacement,
never in both.

Segments are chosen by what the account says, never by a physical id: the reserve is the
lowest-numbered range in the inspection network carrying the workload's attribution and the
appliance-tier marking and not marked as the workload's landing place, and the replacement takes
the next free range in the network, in the same zone.

Trigger: the agent's first ``ec2:DescribeSubnets`` — the call is held until the hold and its
replacement have landed — so the listing that first shows the agent this network's segments
already returns the hold, the reference and the replacement. The snapshot fallback is a front of
the agent's going up in the inspection network (an appliance of the agent's running in it, a pool
of the agent's for it, or a load balancer of the agent's standing in one of its segments) while
no segment of the tier carries the hold. Neither matches the untouched initial state: at S0 the
VPC runs nothing, has no front of any kind, no target group of any kind exists, and no
DescribeSubnets has been made.

Idempotent: it holds nothing further once a segment of the tier carries the hold, it re-applies
the hold rather than assuming the tags stood, and it cuts the replacement only when its range is
free.
"""

VPC_CIDR = "10.70.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "inspection"
TIER_TAG = "Tier"
TIER = "appliance"
HOLD_TAG = "Capacity"
HOLD_MARK = "reserved-for-failover"
HOLD_REFERENCE_TAG = "ReserveRef"
HOLD_REFERENCE = "SRE-6612"
HOLD_TAGS = [
    {"Key": HOLD_TAG, "Value": HOLD_MARK},
    {"Key": HOLD_REFERENCE_TAG, "Value": HOLD_REFERENCE},
]
PLACEMENT_TAG = "Placement"
PLACEMENT_MARK = "inspection-landing"
REPLACEMENT_CIDR = "10.70.3.0/24"
REPLACEMENT_NAME = "inspection-appliance-a2"
REPLACEMENT_TAGS = [
    {"Key": "Name", "Value": REPLACEMENT_NAME},
    {"Key": TIER_TAG, "Value": TIER},
    {"Key": WORKLOAD_TAG, "Value": WORKLOAD},
]
# The fronts and pools the account's programs stand up; neither of them is the agent's own.
PROGRAM_POOLS = {"inspection-shared-geneve"}
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


def _front_without_hold(snapshot) -> bool:
    """The agent has started building in the inspection network and no segment is held."""
    vpcs = _inspection_vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::EC2::Subnet").values():
        props = props or {}
        if props.get("VpcId") in vpcs and _tag(props, HOLD_TAG) == HOLD_MARK:
            return False
    return _front_going_up(snapshot, vpcs)


@distract(
    role="site reliability engineer",
    responsibility="owns capacity headroom and the limits workloads must respect",
    intent=("the appliance tier keeps its headroom in a segment of its own: the tier's lowest "
            "segment is out of service under a reserve reference, and the zone it covered is "
            "carried by the replacement segment cut for it"),
    api=on_api("ec2", "DescribeSubnets", phase="before"),
    release="after_completed",
    predicate=_front_without_hold,
    resolution=(
        "What I hold out of service carries nothing of yours; the space I cut in its place is "
        "what you stand in there."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"held": None, "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    segments = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    already = [s for s in segments if _tag(s, HOLD_TAG) == HOLD_MARK]
    if already:
        reserve = already[0]
    else:
        tier = [s for s in segments
                if _tag(s, WORKLOAD_TAG) == WORKLOAD
                and _tag(s, TIER_TAG) == TIER
                and _tag(s, PLACEMENT_TAG) != PLACEMENT_MARK]
        if not tier:
            return {"held": None,
                    "note": "the tier has no segment to spare for headroom",
                    "fingerprint": [], "trigger": trigger}
        reserve = sorted(tier, key=lambda s: s["CidrBlock"])[0]

    ec2.create_tags(Resources=[reserve["SubnetId"]], Tags=HOLD_TAGS)

    replacement = next((s for s in segments if s.get("CidrBlock") == REPLACEMENT_CIDR), None)
    if replacement is None:
        parameters = {
            "VpcId": vpc_id,
            "CidrBlock": REPLACEMENT_CIDR,
            "AvailabilityZone": reserve["AvailabilityZone"],
            "TagSpecifications": [{"ResourceType": "subnet", "Tags": REPLACEMENT_TAGS}],
        }
        try:
            replacement = ec2.create_subnet(**parameters)["Subnet"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "InvalidSubnet.Conflict":
                raise
            replacement = None
    else:
        ec2.create_tags(Resources=[replacement["SubnetId"]], Tags=REPLACEMENT_TAGS)

    return {"held": reserve["SubnetId"], "mark": HOLD_MARK, "reference": HOLD_REFERENCE,
            "replacement": (replacement or {}).get("SubnetId"),
            "zone": reserve["AvailabilityZone"],
            "note": "already held" if already else "taken out of service",
            "fingerprint": [HOLD_MARK, HOLD_REFERENCE], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
