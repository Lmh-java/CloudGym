from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The platform team applying the account's network naming convention.

Shared networks in this account are named by the platform, not by the workload that happens to
sit in them, so the reporting service's VPC — the 10.0.0.0/16 network carrying the service's
attribution — is renamed to the convention. Nothing else about it changes: its range, its
attribution and everything inside it stay exactly as they are, so the network is still the same
one, under the name the account gives it.

Trigger: the agent's first ``ec2:DescribeVpcs`` — the call is held until the rename has landed,
so the first listing the agent ever gets back already shows the convention name — with a
snapshot fallback for a workload having moved into the network, space it cut for itself or a
server running, while the name is still the workload's. Neither matches the untouched initial
state: at S0 the VPC still carries the workload name and holds no subnet at all.

Idempotent: it finds the network by range and attribution, never by the name it is about to
change, and writes nothing when the convention name already stands.
"""

VPC_CIDR = "10.0.0.0/16"
APP = "reporting"
CONVENTION_NAME = "net-use1-vpc-02"
# The mark the network team puts on the segment it places: space the workload did not cut, so
# its presence alone is not the workload having moved in.
PLACEMENT_TAG = "Placement"
PLACEMENT_MARK = "net-placed-a7"


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _named_by_the_workload(snapshot) -> bool:
    """A workload has moved into the service's network — space it cut for itself, or a server
    running — and the network is still not named to the convention."""
    unconventional = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR or _tag(props, "App") != APP:
            continue
        if _tag(props, "Name") != CONVENTION_NAME:
            unconventional.add(props.get("VpcId") or identifier)
    if not unconventional:
        return False
    if any((props or {}).get("VpcId") in unconventional
           for props in _resources(snapshot, "AWS::EC2::Instance").values()):
        return True
    return any((props or {}).get("VpcId") in unconventional
               and _tag(props, PLACEMENT_TAG) != PLACEMENT_MARK
               for props in _resources(snapshot, "AWS::EC2::Subnet").values())


@distract(
    role="platform engineer",
    responsibility="owns naming conventions across the account",
    intent=("every shared network in the account carries the platform's naming rather than a "
            "workload's, so the reporting service's network is the VPC on 10.0.0.0/16 named "
            "net-use1-vpc-02, unchanged in every other respect"),
    api=on_api("ec2", "DescribeVpcs", phase="before"),
    release="after_completed",
    predicate=_named_by_the_workload,
    resolution=(
        "Names in this account are ours to set; what carries a name keeps it, and nothing is "
        "stood up a second time."
    ),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:App", "Values": [APP]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"renamed": None, "note": f"no VPC on {VPC_CIDR} attributed to {APP}",
                "fingerprint": [], "trigger": trigger}

    vpc = sorted(vpcs, key=lambda v: v["VpcId"])[0]
    previous = None
    for tag in vpc.get("Tags") or []:
        if tag.get("Key") == "Name":
            previous = tag.get("Value")

    if previous == CONVENTION_NAME:
        return {"renamed": vpc["VpcId"], "name": CONVENTION_NAME, "note": "convention already set",
                "fingerprint": [CONVENTION_NAME], "trigger": trigger}

    ec2.create_tags(Resources=[vpc["VpcId"]],
                    Tags=[{"Key": "Name", "Value": CONVENTION_NAME}])
    return {"renamed": vpc["VpcId"], "name": CONVENTION_NAME, "previous": previous,
            "fingerprint": [CONVENTION_NAME], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
