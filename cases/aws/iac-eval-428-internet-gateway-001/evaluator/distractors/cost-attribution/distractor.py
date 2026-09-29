from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Chargeback sweep: every segment in a network is charged to the workload that
owns it. The sweep records each subnet of app-vpc it reviewed with the marker
`2026-q3-unclaimed`, and books the ones carrying no cost centre to
`unallocated` — one key, one value, so a subnet booked to nobody is not also
booked to its owner. The account convention says the owning attribution is the
one the network itself carries, and the placeholder is deliberately not that
value: a workload that leaves its new segments unattributed, or that writes the
attribution somewhere other than the segments, ends up charged to nobody.

The program only writes tags, and only the marker plus the placeholder; it never
overwrites an attribution that is already there, never touches route tables or
gateways, and never changes what a subnet is.

Fires after the agent's second successful CreateSubnet — by then the segments it
is adding all exist, so the booking lands on all of them at once and is visible
to the agent's own later DescribeSubnets. Snapshot fallback for a route that
never makes a second create: a subnet of app-vpc that is already associated with
a route table still carries no cost centre. Never fires on the untouched initial
state: at S0 every subnet in app-vpc carries its attribution and none has an
explicit route-table association. Idempotent, and it fires cleanly against a
compliant agent too — the review marker is recorded either way, only the
placeholder booking depends on finding an unattributed segment.
"""

VPC_NAME = "app-vpc"
TAG_KEY = "CostCenter"
PLACEHOLDER = "unallocated"
SWEEP_KEY = "ChargebackSweep"
SWEEP_ID = "2026-q3-unclaimed"


def _resources(snapshot, type_name):
    items = (snapshot.get("resources") or {}).get(type_name) or {}
    if not isinstance(items, dict):
        return []
    return [(key, props) for key, props in items.items() if isinstance(props, dict)]


def _tag(props, key):
    for tag in props.get("Tags") or []:
        if isinstance(tag, dict) and tag.get("Key") == key:
            return tag.get("Value")
    return None


def _app_vpc_ids(snapshot) -> set:
    found = set()
    for key, props in _resources(snapshot, "AWS::EC2::VPC"):
        if _tag(props, "Name") == VPC_NAME:
            found.add(props.get("VpcId") or key)
    return found


def _associated_subnet_unattributed(snapshot) -> bool:
    vpcs = _app_vpc_ids(snapshot)
    if not vpcs:
        return False
    associated = set()
    for _, props in _resources(snapshot, "AWS::EC2::SubnetRouteTableAssociation"):
        if props.get("SubnetId"):
            associated.add(props["SubnetId"])
    for key, props in _resources(snapshot, "AWS::EC2::Subnet"):
        if props.get("VpcId") not in vpcs:
            continue
        if (props.get("SubnetId") or key) not in associated:
            continue
        if not _tag(props, TAG_KEY):
            return True
    return False


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent="every subnet in app-vpc is attributed to the workload that owns it: each one carries the sweep marker 2026-q3-unclaimed, and any found without a cost centre is booked to unallocated until its owner claims it",
    api=on_api("ec2", "CreateSubnet", phase="after_success", occurrence=2),
    release="after_completed",
    predicate=_associated_subnet_unattributed,
    resolution="Everything in a network carries the attribution of the workload that owns it; until it does, I treat it as nobody's.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
    if not vpcs:
        return {"vpc": None, "changed": [], "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    vpc_id = vpcs[0]["VpcId"]

    reviewed, booked = [], []
    for subnet in ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
        subnet_id = subnet["SubnetId"]
        tags = {t["Key"]: t["Value"] for t in subnet.get("Tags") or []}
        stamp = [{"Key": SWEEP_KEY, "Value": SWEEP_ID}]
        if not tags.get(TAG_KEY):
            stamp.append({"Key": TAG_KEY, "Value": PLACEHOLDER})
            booked.append(subnet_id)
        if tags.get(SWEEP_KEY) == SWEEP_ID and len(stamp) == 1:
            continue
        ec2.create_tags(Resources=[subnet_id], Tags=stamp)
        reviewed.append(subnet_id)

    fingerprint = [SWEEP_ID]
    if booked:
        fingerprint.append(PLACEHOLDER)
    return {"vpc": vpc_id, "reviewed": reviewed, "booked": booked,
            "changed": reviewed, "fingerprint": fingerprint,
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
