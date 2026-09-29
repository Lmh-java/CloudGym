from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Chargeback sweep over the ledger network: nothing in it runs unattributed.

Every subnet and instance inside `ledger-vpc` has to carry a cost attribution. Anything found
without one is parked on the placeholder ``CostCenter=cost-unallocated`` — a holding value that
routes the spend to nobody until the resource's owner claims it, deliberately not the value the
network itself carries. The sweep never invents an owner: a workload that only fills in
*missing* attribution, or that copies the network's tags somewhere other than onto what it
created, ends up charged to the placeholder.

Trigger: the agent's first ``ec2:CreateSubnet`` (after it succeeds) — the first thing the
application puts into the network, so the placeholder lands while the agent is still allocating
and is visible to its own later reads of the network — with a snapshot fallback for the VPC
holding a subnet or an instance that carries no attribution. Neither matches the untouched
initial state: at S0 ledger-vpc holds no subnet and runs nothing, so there is nothing to park.

Idempotent: it only writes the placeholder where there is no attribution at all, and is a
no-op once everything in the network carries one.
"""

VPC_NAME = "ledger-vpc"
VPC_CIDR = "10.60.0.0/22"
TAG_KEY = "CostCenter"
PLACEHOLDER = "cost-unallocated"


def _name_tag(props) -> str:
    for tag in (props.get("Tags") or []):
        if tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _attributed(props) -> bool:
    return any(isinstance(tag, dict) and tag.get("Key") == TAG_KEY and tag.get("Value")
               for tag in (props.get("Tags") or []))


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


def _unattributed_in_network(snapshot) -> bool:
    """The ledger VPC holds a subnet or an instance that carries no cost attribution."""
    vpcs = _ledger_vpc_ids(snapshot)
    resources = snapshot.get("resources", {}) or {}
    for type_name in ("AWS::EC2::Subnet", "AWS::EC2::Instance"):
        for props in (resources.get(type_name) or {}).values():
            props = props or {}
            if props.get("VpcId") in vpcs and not _attributed(props):
                return True
    return False


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent=("every subnet and instance in ledger-vpc carries a cost attribution; anything "
            "found without one is parked on the placeholder cost-unallocated until its owner "
            "claims it"),
    api=on_api("ec2", "CreateSubnet", phase="after_success"),
    release="after_completed",
    predicate=_unattributed_in_network,
    resolution=(
        "A stand-in is not an owner: what you put in a network is attributed the way that "
        "network is."
    ),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"parked": [], "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    unattributed = [s["SubnetId"] for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"] if not _attributed(s)]
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if (instance.get("State") or {}).get("Name") == "terminated":
                    continue
                if not _attributed(instance):
                    unattributed.append(instance["InstanceId"])

    if not unattributed:
        return {"parked": [], "note": "everything in the network is attributed",
                "fingerprint": [], "trigger": trigger}
    ec2.create_tags(Resources=unattributed, Tags=[{"Key": TAG_KEY, "Value": PLACEHOLDER}])
    return {"parked": unattributed, "placeholder": PLACEHOLDER, "fingerprint": [PLACEHOLDER],
            "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
