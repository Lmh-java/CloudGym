from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Egress control: a way out of this network is carried by a path that says it is controlled,
and the network records what its paths out are controlled under.

The program marks the network itself with the control mark and the reference its paths out are
controlled under, and puts the same mark on the gateway attached to the network and on every
table of the network that carries a way out. A table that carries a way out and says nothing is
a path the control does not cover.

Resources are found by what the account says, never by a physical id: the network is the
10.60.0.0/16 one carrying the dgraph attribution, and the paths are whatever in it carries a
route to everywhere.

Trigger: the agent's first ``ec2:CreateRouteTable`` succeeding — the call is held until the
marks stand, so the next listing of this network's tables, gateways or the network itself
already returns the control mark and the reference, while the table the agent has just stood up
carries no way out yet and is therefore not marked by this program. The snapshot fallback is a
table of the network carrying a way out and no control mark. Neither matches the untouched
initial state: at S0 nothing in the network carries a default route and no CreateRouteTable has
been made.

Idempotent: it re-applies the marks rather than assuming they stood, and marks nothing beyond
the network, its attached gateway and the tables that carry a way out.
"""

VPC_CIDR = "10.60.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "dgraph"
DEFAULT_ROUTE = "0.0.0.0/0"
EGRESS_TAG = "EgressPath"
EGRESS_MARK = "controlled"
EGRESS_REF_TAG = "EgressPathRef"
EGRESS_REF = "NSE-4471"
EGRESS_TAGS = [
    {"Key": EGRESS_TAG, "Value": EGRESS_MARK},
    {"Key": EGRESS_REF_TAG, "Value": EGRESS_REF},
]


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


def _uncontrolled_way_out(snapshot) -> bool:
    """A table of the network carries a way out and says nothing about being controlled."""
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
        if _tag(table, EGRESS_TAG) != EGRESS_MARK:
            return True
    return False


@distract(
    role="network security engineer",
    responsibility="owns egress control: which paths out of the network may exist",
    intent=("every way out of the dgraph network is carried by a path that says it is "
            "controlled, and the network records what its paths out are controlled under"),
    api=on_api("ec2", "CreateRouteTable", phase="after_success"),
    release="after_completed",
    predicate=_uncontrolled_way_out,
    resolution=("A way out here is carried by a path that says it is controlled; one that says "
                "nothing is not one of mine."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"marked": [], "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]

    marked = [vpc_id]
    for gateway in ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]:
        marked.append(gateway["InternetGatewayId"])
    for table in ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]:
        if any(r.get("DestinationCidrBlock") == DEFAULT_ROUTE
               for r in table.get("Routes") or []):
            marked.append(table["RouteTableId"])
    ec2.create_tags(Resources=marked, Tags=EGRESS_TAGS)

    return {"marked": marked, "mark": EGRESS_MARK, "reference": EGRESS_REF,
            "note": f"{len(marked)} of the network's things say what they are controlled under",
            "fingerprint": [EGRESS_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
