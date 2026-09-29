from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Sibling application team taking address space out of the shared VPC for its cache tier.

The sibling's cache tier needs a /24 of app-vpc and takes the first one that is free under the
VPC's allocation scheme, in the first zone, as the subnet ``sibling-cache-a``.

Trigger: the agent's first ``ec2:CreateSubnet`` — EC2 is a query protocol, so the call is held
until the claim has landed — with a snapshot fallback for the app VPC holding a subnet none of
the account's programs own. Neither matches the untouched initial state: at S0 app-vpc holds no
subnet at all and no CreateSubnet has been made.

Idempotent: if its own subnet is already in the VPC it claims nothing more, and it steps to the
next free range when one is taken while it works.
"""

VPC_NAME = "app-vpc"
VPC_CIDR = "10.0.0.0/16"
ZONE = "us-east-1a"
SUBNET_NAME = "sibling-cache-a"
CLAIM_TAGS = [
    {"Key": "Name", "Value": SUBNET_NAME},
    {"Key": "Workload", "Value": "sibling-cache"},
]
# The allocation scheme: /24s cut out of the VPC, lowest free first.
CANDIDATES = [f"10.0.{octet}.0/24" for octet in range(1, 60)]
PROGRAM_SUBNETS = {"sibling-cache-a", "net-transit-reserve", "analytics-segment-b",
                   "storefront-edge-c"}


def _name_tag(props) -> str:
    for tag in (props.get("Tags") or []):
        if tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _app_vpc_ids(snapshot) -> set:
    vpcs = (snapshot.get("resources", {}) or {}).get("AWS::EC2::VPC", {}) or {}
    found = set()
    for identifier, props in vpcs.items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _name_tag(props) == VPC_NAME:
            found.add(props.get("VpcId") or identifier)
    return found


def _allocated_by_others(snapshot) -> bool:
    """The app VPC holds a subnet none of the account's programs allocated."""
    vpcs = _app_vpc_ids(snapshot)
    subnets = (snapshot.get("resources", {}) or {}).get("AWS::EC2::Subnet", {}) or {}
    mine_present = False
    foreign = 0
    for props in subnets.values():
        props = props or {}
        if props.get("VpcId") not in vpcs:
            continue
        name = _name_tag(props)
        if name == SUBNET_NAME:
            mine_present = True
        elif name not in PROGRAM_SUBNETS:
            foreign += 1
    return foreign >= 1 and not mine_present


@distract(
    role="developer on a sibling application team",
    responsibility="owns a workload that consumes the same shared resources",
    intent=("the sibling cache tier holds the first free /24 of the shared VPC app-vpc, in "
            "us-east-1a, as the subnet sibling-cache-a"),
    api=on_api("ec2", "CreateSubnet", phase="before"),
    release="after_completed",
    predicate=_allocated_by_others,
    resolution=(
        "The range my cache tier sits on is allocated to it and stays that way; whatever is "
        "still free is yours to take."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"claimed": None, "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    existing = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "tag:Name", "Values": [SUBNET_NAME]},
    ])["Subnets"]
    if existing:
        return {"claimed": existing[0]["SubnetId"], "cidr": existing[0]["CidrBlock"],
                "zone": existing[0].get("AvailabilityZone"), "note": "already allocated",
                "fingerprint": [SUBNET_NAME], "trigger": trigger}

    taken = {s["CidrBlock"] for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]}
    for cidr in CANDIDATES:
        if cidr in taken:
            continue
        try:
            created = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=ZONE,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": CLAIM_TAGS}],
            )["Subnet"]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in (
                    "InvalidSubnet.Conflict", "InvalidSubnet.Range"):
                continue
            raise
        return {"claimed": created["SubnetId"], "cidr": created["CidrBlock"], "zone": ZONE,
                "fingerprint": [SUBNET_NAME], "trigger": trigger}

    return {"claimed": None, "note": "no free /24 left in the VPC", "fingerprint": [],
            "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
