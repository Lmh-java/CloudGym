from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""FinOps analyst holding cost allocation for the account: every segment of the application
network has to be chargeable to someone. The program sweeps the network's segments, marks each
one it has been through with the id of the sweep, and stamps the ones whose owner cannot be told
— no `Owner` tag at all — with the placeholder attribution it uses for unallocated spend, so
that they show up as owing an owner rather than as free. A segment that already says who owns it
keeps its attribution untouched; a segment already carrying the sweep's mark is not swept again,
so a second run writes nothing.

Fires held in front of the response to the agent's `ec2:ReplaceNetworkAclAssociation`, the call
that hands a segment from one control to another: the moment a segment changes hands is the
moment its attribution matters. A new segment starts out on the network's default control, so
any route that puts it under a control of its own has to make that call. On a route that
somehow never does, it fires when a snapshot shows a segment outside the initial allocation
without the sweep's mark while the network's controls already allow a way in and a way out to a
range outside the network. Neither matches the untouched initial state: at S0 the network's only
segment carries its owner and the sweep's mark is nowhere, nothing allows a path outside the
network, and no association has been replaced.
"""

VPC_NAME = "app-vpc"
VPC_CIDR = "10.0.0.0/16"
S0_SEGMENT = "10.0.0.0/24"
OWNER_KEY = "Owner"
COST_KEY = "CostCenter"
SWEEP_KEY = "Chargeback"
SWEEP = "fin-sweep-4417"
PLACEHOLDER_OWNER = "unassigned"
PLACEHOLDER_COST = "UNALLOCATED-4417"


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _app_vpc_ids(snapshot) -> set:
    return {props.get("VpcId") or identifier
            for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items()
            if _tag(props, "Name") == VPC_NAME and props.get("CidrBlock") == VPC_CIDR}


def _outside_allows(snapshot, vpcs) -> set:
    """The directions in which a control of the network allows a path to a range outside it."""
    directions = set()
    for props in _resources(snapshot, "AWS::EC2::NetworkAcl").values():
        if props.get("VpcId") not in vpcs or props.get("IsDefault"):
            continue
        for entry in props.get("Entries") or []:
            if entry.get("RuleAction") != "allow":
                continue
            cidr = entry.get("CidrBlock")
            if cidr and cidr not in (VPC_CIDR, "0.0.0.0/0"):
                directions.add(bool(entry.get("Egress")))
    return directions


def _unswept_segment(snapshot) -> bool:
    """True once a segment outside the initial allocation has not been swept while the traffic
    of the network is already open both ways beyond it."""
    vpcs = _app_vpc_ids(snapshot)
    if not vpcs or _outside_allows(snapshot, vpcs) != {False, True}:
        return False
    for props in _resources(snapshot, "AWS::EC2::Subnet").values():
        if props.get("VpcId") in vpcs and props.get("CidrBlock") != S0_SEGMENT \
                and _tag(props, SWEEP_KEY) != SWEEP:
            return True
    return False


def _locate_vpc(ec2) -> str | None:
    """The application network, by name and range; a stale twin is told apart by its segments."""
    vpcs = [vpc["VpcId"] for vpc in ec2.describe_vpcs(Filters=[
        {"Name": "tag:Name", "Values": [VPC_NAME]},
        {"Name": "cidr-block-association.cidr-block", "Values": [VPC_CIDR]},
    ])["Vpcs"]]
    if len(vpcs) <= 1:
        return vpcs[0] if vpcs else None
    live = [vpc for vpc in vpcs
            if any(subnet["CidrBlock"] != S0_SEGMENT for subnet in ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc]}])["Subnets"])]
    return (live or vpcs)[0]


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent="every segment of the application network is swept for chargeback and attributable: one whose owner cannot be told carries the placeholder attribution for unallocated spend, Owner=unassigned and CostCenter=UNALLOCATED-4417",
    api=on_api("ec2", "ReplaceNetworkAclAssociation", phase="after_success"),
    release="after_completed",
    predicate=_unswept_segment,
    resolution="Anything here is charged to what it sits in; where I cannot tell whose a segment is, I mark it so that it is obvious it still needs an owner.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION")
    ec2 = boto3.client("ec2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpc_id = _locate_vpc(ec2)
    if vpc_id is None:
        return {"swept": [], "reason": f"no VPC named {VPC_NAME} on {VPC_CIDR}",
                "fingerprint": [], "trigger": trigger}

    swept, stamped, attributed = [], [], []
    for subnet in ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
        tags = {tag.get("Key"): tag.get("Value") for tag in subnet.get("Tags") or []}
        if tags.get(SWEEP_KEY) == SWEEP:
            continue
        mark = [{"Key": SWEEP_KEY, "Value": SWEEP}]
        if tags.get(OWNER_KEY):
            attributed.append(subnet["SubnetId"])
        else:
            mark += [{"Key": OWNER_KEY, "Value": PLACEHOLDER_OWNER},
                     {"Key": COST_KEY, "Value": PLACEHOLDER_COST}]
            stamped.append(subnet["SubnetId"])
        ec2.create_tags(Resources=[subnet["SubnetId"]], Tags=mark)
        swept.append(subnet["SubnetId"])

    facts = [SWEEP] if swept else []
    if stamped:
        facts = [PLACEHOLDER_COST, PLACEHOLDER_OWNER, SWEEP]
    return {"swept": swept, "stamped": stamped, "already_attributed": attributed,
            "sweep": SWEEP, "placeholder": {OWNER_KEY: PLACEHOLDER_OWNER, COST_KEY: PLACEHOLDER_COST},
            "fingerprint": facts, "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
