from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network team holding address space in the tight ledger network for the account's transit segment.

`ledger-vpc` is a /22 and the account cuts /25s out of it, so every range taken is a range
nobody else can have. The reservation takes the lowest /25 of the VPC that is free at the
moment it is made, in the first zone, as the subnet ``net-transit-hold``. What was free when
the application read the network is therefore not what is free when it writes.

Trigger: the agent's ``ec2:DescribeVpcs`` — the read every route makes to find the network it
was asked to work in, and the one point of the route no subnet write shares — with a snapshot
fallback for the VPC holding a subnet none of the account's programs allocated while the
reservation is absent. The call is held until the reservation has landed. Neither matches the
untouched initial state: at S0 ledger-vpc holds no subnet at all and the agent has made no call.

Idempotent: if the reservation is already in the VPC it takes nothing more, and it steps to the
next free range when one is taken while it works.
"""

VPC_NAME = "ledger-vpc"
VPC_CIDR = "10.60.0.0/22"
ZONE = "us-east-1a"
SUBNET_NAME = "net-transit-hold"
CLAIM_TAGS = [
    {"Key": "Name", "Value": SUBNET_NAME},
    {"Key": "Allocation", "Value": "transit-reserved"},
]
# The account's allocation scheme: /25s cut out of the /22, lowest free first.
CANDIDATES = [f"10.60.{octet}.{half}/25" for octet in range(4) for half in (0, 128)]
PROGRAM_SUBNETS = {"net-transit-hold", "clearing-tier-b", "ledger-edge-c"}


def _name_tag(props) -> str:
    for tag in (props.get("Tags") or []):
        if tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _ledger_vpc_ids(snapshot) -> set:
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
    """The ledger VPC holds a subnet none of the account's programs allocated, and no reservation."""
    vpcs = _ledger_vpc_ids(snapshot)
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
    role="network engineer",
    responsibility="owns the account's address space and how it is allocated and reserved",
    intent=("the account's transit reservation holds the lowest /25 of the tight shared VPC "
            "ledger-vpc that is free when it is made, in us-east-1a, as the subnet "
            "net-transit-hold"),
    api=on_api("ec2", "DescribeVpcs", phase="after_success"),
    release="after_completed",
    predicate=_allocated_by_others,
    resolution=(
        "The range I am holding is reserved and stays reserved; what is free at the moment "
        "you allocate is what you may take."
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
        return {"reserved": None, "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    existing = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "tag:Name", "Values": [SUBNET_NAME]},
    ])["Subnets"]
    if existing:
        return {"reserved": existing[0]["SubnetId"], "cidr": existing[0]["CidrBlock"],
                "zone": existing[0].get("AvailabilityZone"), "note": "already reserved",
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
        return {"reserved": created["SubnetId"], "cidr": created["CidrBlock"], "zone": ZONE,
                "fingerprint": [SUBNET_NAME], "trigger": trigger}

    return {"reserved": None, "note": "no free /25 left in the VPC", "fingerprint": [],
            "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
