from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Chargeback attribution: what belongs to a network is charged where that network is charged,
so nothing standing in it is charged nowhere.

The program reads the attribution the network itself carries and puts it on everything of the
network that is missing it — its segments, its tables and the gateways attached to it — and
stamps each of them, and the network, with the reference the sweep is run under. It writes no
Name: a name is per-resource, the attribution is the network's.

Resources are found by what the account says, never by a physical id: the network is the
10.60.0.0/16 one carrying the dgraph attribution, and what belongs to it is what sits in it.

Trigger: the agent's first ``ec2:DescribeInternetGateways`` — the call is held until the sweep
has run, so the listing that first shows the agent this account's gateways already returns the
chargeback reference on the one attached to this network, and the network itself carries it from
then on. The snapshot fallback is a table of the network carrying a way out while carrying no
chargeback reference. Neither matches the untouched initial state: at S0 nothing in the network
carries a default route and no DescribeInternetGateways has been made.

Idempotent: it stamps only what is missing the attribution, re-applies the reference rather than
assuming it stood, and does nothing at all when the network carries no attribution to spread.
"""

VPC_CIDR = "10.60.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "dgraph"
DEFAULT_ROUTE = "0.0.0.0/0"
CHARGE_TAG = "CostCenter"
CHARGE_REF_TAG = "ChargebackRef"
CHARGE_REF = "FIN-8821"


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _network_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _way_out_charged_nowhere(snapshot) -> bool:
    """Something in the network carries a way out and says nothing about who pays for it."""
    vpcs = _network_ids(snapshot)
    if not vpcs:
        return False
    tables = {}
    for identifier, props in _resources(snapshot, "AWS::EC2::RouteTable").items():
        props = props or {}
        if props.get("VpcId") in vpcs:
            tables[props.get("RouteTableId") or identifier] = props
    for props in _resources(snapshot, "AWS::EC2::Route").values():
        props = props or {}
        if props.get("DestinationCidrBlock") != DEFAULT_ROUTE:
            continue
        table = tables.get(props.get("RouteTableId"))
        if table is None:
            continue
        if not _tag(table, CHARGE_REF_TAG):
            return True
    return False


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent=("everything that belongs to the dgraph network carries the attribution the network "
            "is charged under, so nothing it costs is charged nowhere"),
    api=on_api("ec2", "DescribeInternetGateways", phase="before"),
    release="after_completed",
    predicate=_way_out_charged_nowhere,
    resolution=("What stands in a network is charged where that network is charged; mine is not "
                "the only thing carrying that."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"stamped": [], "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc = sorted(vpcs, key=lambda v: v["VpcId"])[0]
    vpc_id = vpc["VpcId"]
    attribution = _tag(vpc, CHARGE_TAG)
    if not attribution:
        return {"stamped": [], "note": "the network carries no attribution to spread",
                "fingerprint": [], "trigger": trigger}

    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    belongs = [(vpc_id, vpc)]
    belongs += [(s["SubnetId"], s) for s in ec2.describe_subnets(Filters=in_vpc)["Subnets"]]
    belongs += [(t["RouteTableId"], t)
                for t in ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]]
    belongs += [(g["InternetGatewayId"], g) for g in ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]]

    stamped = []
    for identifier, props in belongs:
        tags = [{"Key": CHARGE_REF_TAG, "Value": CHARGE_REF}]
        if _tag(props, CHARGE_TAG) != attribution:
            tags.append({"Key": CHARGE_TAG, "Value": attribution})
            stamped.append(identifier)
        ec2.create_tags(Resources=[identifier], Tags=tags)

    return {"stamped": stamped, "attribution": attribution, "reference": CHARGE_REF,
            "note": f"{len(belongs)} resources of the network carry the attribution",
            "fingerprint": [CHARGE_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
