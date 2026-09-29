from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network team cutting the account's transit segment out of the address plan.

The segment takes the lowest range of the account's 10.0.0.0/8 plan that is free when the cut
is made, starting at 10.1.0.0/16, as the network named ``net-transit-segment``. "Free" is read
the way the account keeps its plan: no network holds the range (first or further range), and no
allocation recorded on the shared platform network names it. The cut steps upward when its
range is already held or recorded, so it never takes space that is already someone's.

Trigger: the agent's first ``ec2:DescribeVpcs``, held until the cut has landed, so the survey a
free range would be derived from is already out of date when it arrives; with a snapshot
fallback for "a network tagged Name=vpc is in the account and the transit segment is not".
Neither matches the untouched initial state: at S0 the account holds only the shared platform
network, nothing is tagged Name=vpc, and no DescribeVpcs has been made.

Idempotent: when the transit segment is already in the account it takes nothing more.
"""

PLATFORM_NAME = "platform-vpc"
SEGMENT_NAME = "net-transit-segment"
AGENT_VPC_NAME = "vpc"
CLAIM = "10.1.0.0/16"
RECORD_PREFIX = "allocation:"


def _name_tag(props) -> str:
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _vpcs(snapshot):
    return (snapshot.get("resources", {}) or {}).get("AWS::EC2::VPC", {}) or {}


def _agent_network_without_segment(snapshot) -> bool:
    """A network tagged Name=vpc is in the account and the transit segment is not."""
    named = [props or {} for props in _vpcs(snapshot).values()]
    return (any(_name_tag(props) == AGENT_VPC_NAME for props in named)
            and not any(_name_tag(props) == SEGMENT_NAME for props in named))


def _allocated(ec2) -> list:
    """Every range the account holds on a network or records as reserved."""
    import ipaddress

    ranges = []
    for vpc in ec2.describe_vpcs()["Vpcs"]:
        associations = vpc.get("CidrBlockAssociationSet") or [{"CidrBlock": vpc.get("CidrBlock")}]
        for association in associations:
            block = association.get("CidrBlock")
            state = (association.get("CidrBlockState") or {}).get("State", "associated")
            if not block or state not in ("associated", "associating"):
                continue
            try:
                ranges.append(ipaddress.ip_network(block))
            except ValueError:
                continue
        for tag in vpc.get("Tags") or []:
            if not str(tag.get("Key") or "").startswith(RECORD_PREFIX):
                continue
            try:
                ranges.append(ipaddress.ip_network(tag.get("Value") or ""))
            except ValueError:
                continue
    return ranges


def _free_range(ec2, start: str) -> str | None:
    """The lowest /16 of the account's plan, from ``start`` upward, that nothing holds."""
    import ipaddress

    taken = _allocated(ec2)
    first = int(start.split(".")[1])
    for octet in range(first, 255):
        candidate = ipaddress.ip_network(f"10.{octet}.0.0/16")
        if not any(candidate.overlaps(held) for held in taken):
            return str(candidate)
    return None


@distract(
    role="network engineer",
    responsibility="owns the account's address space and how it is allocated and reserved",
    intent=("the account's transit segment holds a /16 of the account's plan that is free when "
            "it is cut, as the network named net-transit-segment"),
    api=on_api("ec2", "DescribeVpcs", phase="after_success"),
    release="after_completed",
    predicate=_agent_network_without_segment,
    resolution=("The range that segment sits on is allocated to it and stays that way; what is "
                "still free is yours to take."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    already = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [SEGMENT_NAME]}])["Vpcs"]
    if already:
        return {"segment": already[0]["VpcId"], "cidr": already[0]["CidrBlock"],
                "note": "already cut", "fingerprint": [SEGMENT_NAME], "trigger": trigger}

    cidr = _free_range(ec2, CLAIM)
    if cidr is None:
        return {"segment": None, "cidr": None, "note": "the plan has no free /16 left",
                "fingerprint": [], "trigger": trigger}

    created = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": SEGMENT_NAME},
            {"Key": "Allocation", "Value": "transit-segment"},
        ]}],
    )["Vpc"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[created["VpcId"]])
    return {"segment": created["VpcId"], "cidr": cidr, "fingerprint": [SEGMENT_NAME],
            "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
