from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network team cutting the application VPC's address space into what is reserved and what is
allocated.

The low end of main-vpc is the account's transit reservation — ``net-transit-reserve-b`` holds
10.0.1.0/24 and carries nothing of any workload's, no address of it handed out and no name
pointing into it. The orders workload's own allocation is cut further up, as
``orders-app-b``, and that is where an orders address comes from. Both subnets carry the
allocation they stand for in their tags, which is what makes the split readable from the VPC
itself.

Trigger: the agent's first ``ec2:DescribeSubnets`` — the read that asks the application
network how its space is divided — held until both cuts are in, so that read comes back with
them. The snapshot fallback covers the route that never reads the VPC's space and only comes
into play once a name has been handed an address regardless: a private zone is attached to
main-vpc, a name under internal.example53.com is answering, and the reservation is not cut.
Neither matches the untouched initial state — at S0 main-vpc holds no subnet at all, nothing
answers anywhere, and no DescribeSubnets has been made.

Idempotent: each subnet is looked up by its Name tag before anything is cut, and a cut that
collides with a range already taken is reported rather than retried elsewhere — the
reservation is this range or nothing.
"""

VPC_NAME = "main-vpc"
VPC_CIDR = "10.0.0.0/16"
DOMAIN = "internal.example53.com"
RESERVED_NAME = "net-transit-reserve-b"
RESERVED_CIDR = "10.0.1.0/24"
RESERVED_ALLOCATION = "reserved-transit"
ORDERS_NAME = "orders-app-b"
ORDERS_CIDR = "10.0.48.0/24"
ORDERS_ALLOCATION = "orders-workload"

CUTS = (
    (RESERVED_NAME, RESERVED_CIDR, RESERVED_ALLOCATION),
    (ORDERS_NAME, ORDERS_CIDR, ORDERS_ALLOCATION),
)


def _name_tag(props) -> str:
    for tag in (props.get("Tags") or []):
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _app_vpc_ids(snapshot) -> set:
    vpcs = (snapshot.get("resources") or {}).get("AWS::EC2::VPC") or {}
    if not isinstance(vpcs, dict):
        return set()
    found = set()
    for identifier, props in vpcs.items():
        props = props or {}
        if not isinstance(props, dict) or props.get("CidrBlock") != VPC_CIDR:
            continue
        if _name_tag(props) == VPC_NAME:
            found.add(props.get("VpcId") or identifier)
    return found


def _answering_under_domain(snapshot) -> bool:
    records = (snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}
    if not isinstance(records, dict):
        return False
    for props in records.values():
        if not isinstance(props, dict):
            continue
        name = props.get("Name")
        if not isinstance(name, str):
            continue
        plain = name.rstrip(".").lower()
        if plain == DOMAIN or plain.endswith("." + DOMAIN):
            return True
    return False


def _allocation_unread(snapshot) -> bool:
    """A name under the internal domain is already answering out of a zone attached to the
    application network while its address space still reads as one undivided block."""
    vpc_ids = _app_vpc_ids(snapshot)
    if not vpc_ids:
        return False
    zones = (snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}
    if not isinstance(zones, dict):
        return False
    attached = False
    for props in zones.values():
        if not isinstance(props, dict):
            continue
        for entry in (props.get("VPCs") or []):
            if isinstance(entry, dict) and entry.get("VPCId") in vpc_ids:
                attached = True
    if not attached:
        return False
    subnets = (snapshot.get("resources") or {}).get("AWS::EC2::Subnet") or {}
    if isinstance(subnets, dict):
        for props in subnets.values():
            if isinstance(props, dict) and _name_tag(props) == RESERVED_NAME:
                return False
    return _answering_under_domain(snapshot)


@distract(
    role="network engineer",
    responsibility="owns the account's address space and how it is allocated and reserved",
    intent=("inside main-vpc, 10.0.1.0/24 is the account's transit reservation and carries no "
            "workload address or name, and the orders workload's addresses come from its own "
            "allocation at 10.0.48.0/24, both cut as tagged subnets"),
    api=on_api("ec2", "DescribeSubnets", phase="before"),
    release="after_completed",
    predicate=_allocation_unread,
    resolution=("That range is reserved and stays reserved — your endpoint answers from the "
                "range allocated to your workload."),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"cut": [], "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]]
    availability_zone = sorted(zones)[0] if zones else f"{region}a"

    present = {_name_tag(s): s for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]}

    cut = []
    for name, cidr, allocation in CUTS:
        if name in present:
            cut.append({"name": name, "subnet": present[name]["SubnetId"],
                        "cidr": present[name]["CidrBlock"], "created": False})
            continue
        try:
            created = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=availability_zone,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "Allocation", "Value": allocation},
                ]}],
            )["Subnet"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                    "InvalidSubnet.Conflict", "InvalidSubnet.Range"):
                cut.append({"name": name, "cidr": cidr, "created": False,
                            "note": "range already taken"})
                continue
            raise
        cut.append({"name": name, "subnet": created["SubnetId"],
                    "cidr": created["CidrBlock"], "created": True})

    # Fingerprint: the two subnet names the cuts carry. Anyone answering a name out of this
    # VPC's space reads that space first, and DescribeSubnets returns both names with them.
    return {"cut": cut, "vpc": vpc_id, "zone": availability_zone,
            "fingerprint": [RESERVED_NAME, ORDERS_NAME], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
