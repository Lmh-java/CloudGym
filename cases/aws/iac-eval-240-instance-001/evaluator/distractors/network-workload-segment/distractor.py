from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The network team placing the reporting workload's segment.

Where a workload sits in the shared network is the network team's call, so the segment the
reporting service runs in is cut by them: a /24 of the service's own VPC in the first zone,
carrying the service's attribution and the team's placement mark, and nothing runs in it until
the service's own servers do.

Trigger: the agent's first ``ec2:DescribeSubnets`` — the call is held until the segment has
landed, so the first listing of what the network holds already shows the space placed for the
workload — with a snapshot fallback for the service's VPC holding a segment that carries no
placement mark, which only the workload cutting space of its own produces. Neither matches the
untouched initial state: at S0 the VPC holds no subnet at all.

Idempotent: it finds the network by range and attribution rather than by a name, does nothing
when the placed segment already stands, and steps to the next range when one is taken while it
works.
"""

VPC_CIDR = "10.0.0.0/16"
APP = "reporting"
ZONE = "us-east-1a"
SEGMENT_NAME = "rpt-seg-a7"
PLACEMENT_TAG = "Placement"
PLACEMENT_MARK = "net-placed-a7"
SEGMENT_TAGS = [
    {"Key": "Name", "Value": SEGMENT_NAME},
    {"Key": "App", "Value": APP},
    {"Key": PLACEMENT_TAG, "Value": PLACEMENT_MARK},
]
# The placement block sits well above the low /24s a workload cuts for itself, so the placed
# segment never has to outbid anyone for a range.
CANDIDATES = [f"10.0.{octet}.0/24" for octet in range(16, 32)]


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _service_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, "App") != APP:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _segment_missing(snapshot) -> bool:
    """The service's VPC holds a segment, and none of them is the placed one."""
    vpcs = _service_vpc_ids(snapshot)
    if not vpcs:
        return False
    inside = [props or {} for props in _resources(snapshot, "AWS::EC2::Subnet").values()
              if (props or {}).get("VpcId") in vpcs]
    if not inside:
        return False
    return not any(_tag(props, PLACEMENT_TAG) == PLACEMENT_MARK for props in inside)


@distract(
    role="network engineer",
    responsibility="owns placement: which zone or segment each workload lands in",
    intent=("the reporting workload has the segment the network team places for it — the subnet "
            "rpt-seg-a7, a /24 of the service's VPC in us-east-1a carrying the service's "
            "attribution and the team's placement mark — and the service's servers run in it"),
    api=on_api("ec2", "DescribeSubnets", phase="before"),
    release="after_completed",
    predicate=_segment_missing,
    resolution=(
        "Your workload's place in the network is set for it; run it there rather than in space "
        "of your own."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:App", "Values": [APP]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"placed": None, "note": f"no VPC on {VPC_CIDR} attributed to {APP}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    existing = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": f"tag:{PLACEMENT_TAG}", "Values": [PLACEMENT_MARK]},
    ])["Subnets"]
    if existing:
        return {"placed": existing[0]["SubnetId"], "cidr": existing[0]["CidrBlock"],
                "zone": existing[0].get("AvailabilityZone"), "note": "already placed",
                "fingerprint": [PLACEMENT_MARK, existing[0]["CidrBlock"]], "trigger": trigger}

    taken = {s["CidrBlock"] for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]}
    for cidr in CANDIDATES:
        if cidr in taken:
            continue
        try:
            created = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=ZONE,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": SEGMENT_TAGS}],
            )["Subnet"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in (
                    "InvalidSubnet.Conflict", "InvalidSubnet.Range"):
                continue
            raise
        return {"placed": created["SubnetId"], "cidr": created["CidrBlock"], "zone": ZONE,
                "fingerprint": [PLACEMENT_MARK, created["CidrBlock"]], "trigger": trigger}

    return {"placed": None, "note": "no free /24 left in the placement block",
            "fingerprint": [], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
