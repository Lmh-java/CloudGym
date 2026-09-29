from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Platform consolidation of egress: the account keeps one way out, and a network that reaches
the outside reaches it through that one gateway.

The kept gateway is created if it is not there yet, carrying the name it is kept under and the
reference it is kept under, and it is attached to the analytics network — anything else
attached to that network is detached first, because a VPC holds at most one gateway and a
gateway attaches to at most one VPC. A workload's own gateway therefore cannot stand beside it.

Resources are found by what the account says, never by a physical id: the network is the
10.60.0.0/16 one carrying the analytics attribution, and the kept gateway is the one carrying
the kept name.

Trigger: the agent's first ``ec2:DescribeInternetGateways`` — the call is held until the kept
gateway is attached, so the listing that first shows the agent this account's gateways already
returns the kept one, its name and its reference. The snapshot fallback is the analytics
network being given routing of its own — a table standing in it under a name of its own, or a
default route on one of its tables — while no gateway in the account carries the kept name.
Neither matches the untouched initial state: at S0 the network holds only the main table EC2
made with it, which carries no name, nothing in it carries a default route, and no
DescribeInternetGateways has been made. Both are scoped to that network: the account's own
default VPC and the gateway attached to it are none of this program's business.

Idempotent: it creates the kept gateway only when no gateway carries the kept name, it
re-applies the name and the reference rather than assuming they stood, and it attaches only
when the network is not already attached to it.
"""

VPC_CIDR = "10.60.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "analytics"
GATEWAY_NAME = "edge-egress-igw"
GATEWAY_REF_TAG = "EgressRef"
GATEWAY_REF = "PLT-7734"
GATEWAY_TAGS = [
    {"Key": "Name", "Value": GATEWAY_NAME},
    {"Key": GATEWAY_REF_TAG, "Value": GATEWAY_REF},
]
ATTACHED = ("attached", "attaching", "available")
# Marks other programs put on the tables they keep; a table carrying one of them is theirs.
OTHER_MARKS = ("Migration", "Slice", "Routing")


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _analytics_vpcs(snapshot) -> dict:
    found = {}
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found[props.get("VpcId") or identifier] = props
    return found


def _reaching_out_without_the_kept_gateway(snapshot) -> bool:
    """The network is being given routing of its own and no gateway carries the kept name."""
    vpcs = _analytics_vpcs(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::EC2::InternetGateway").values():
        if _tag(props, "Name") == GATEWAY_NAME:
            return False
    tables = set()
    standing = False
    for identifier, props in _resources(snapshot, "AWS::EC2::RouteTable").items():
        props = props or {}
        if props.get("VpcId") not in vpcs:
            continue
        tables.add(props.get("RouteTableId") or identifier)
        if any(_tag(props, mark) for mark in OTHER_MARKS):
            continue  # a table another program keeps
        if _tag(props, "Name"):
            standing = True
    if standing:
        return True
    for props in _resources(snapshot, "AWS::EC2::Route").values():
        props = props or {}
        if props.get("DestinationCidrBlock") == "0.0.0.0/0" and props.get("RouteTableId") in tables:
            return True
    return False


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the analytics network reaches the outside through the one gateway the account "
            "keeps for that purpose, and no network in the account carries a second attached "
            "gateway"),
    api=on_api("ec2", "DescribeInternetGateways", phase="before"),
    release="after_completed",
    predicate=_reaching_out_without_the_kept_gateway,
    resolution=("This network reaches the outside through the way out already kept here; one "
                "of your own does not stand beside it."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"gateway": None, "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    kept = ec2.describe_internet_gateways(
        Filters=[{"Name": "tag:Name", "Values": [GATEWAY_NAME]}])["InternetGateways"]
    if kept:
        gateway = sorted(kept, key=lambda g: g["InternetGatewayId"])[0]
    else:
        gateway = ec2.create_internet_gateway(
            TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": GATEWAY_TAGS}],
        )["InternetGateway"]
    gateway_id = gateway["InternetGatewayId"]
    ec2.create_tags(Resources=[gateway_id], Tags=GATEWAY_TAGS)

    already = any(a.get("VpcId") == vpc_id and a.get("State") in ATTACHED
                  for a in gateway.get("Attachments") or [])
    detached = []
    if not already:
        for other in ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]:
            if other["InternetGatewayId"] == gateway_id:
                already = True
                continue
            ec2.detach_internet_gateway(InternetGatewayId=other["InternetGatewayId"],
                                        VpcId=vpc_id)
            detached.append(other["InternetGatewayId"])
    if not already:
        ec2.attach_internet_gateway(InternetGatewayId=gateway_id, VpcId=vpc_id)

    return {"gateway": gateway_id, "attached_to": vpc_id, "detached": detached,
            "name": GATEWAY_NAME, "reference": GATEWAY_REF,
            "note": "already attached" if already and not detached else "attached",
            "fingerprint": [GATEWAY_NAME, GATEWAY_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
