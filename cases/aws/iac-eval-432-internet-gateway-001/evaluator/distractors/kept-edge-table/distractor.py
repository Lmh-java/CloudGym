from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Routing consolidation: the graph-store network's outward routing is carried by one table,
the one the account keeps for it, and that table carries the routing mark and the reference it
is kept under.

The kept table is created in the network if it is not there yet, carrying the name it is kept
under, the routing mark and the reference. A way out that has grown on any other table in the
network is taken off again: a table carries at most one route to a destination, and this
network is allowed one table carrying that destination, so the way out sits either on the kept
table or on a table standing beside it, never on both. Nothing else in the network is touched —
the segments, and the table the closed tier is held on, are left exactly as they are.

Resources are found by what the account says, never by a physical id: the network is the
10.30.0.0/16 one carrying the graph-store attribution, and the kept table is the one in it
carrying the kept name.

Trigger: the agent's first ``ec2:DescribeRouteTables`` — the call is held until the kept table
is in the network, so the listing that first shows the agent this network's tables already
returns the kept one, its routing mark and its reference. The snapshot fallback is a table
standing in the network under a name of its own while no table in it carries the routing mark.
Neither matches the untouched initial state: at S0 the network holds only the main table EC2
made with it, which carries no name and no mark, and no DescribeRouteTables has been made.

Idempotent: it creates the kept table only when no table carries the kept name, it re-applies
the mark rather than assuming the tags stood, and it removes a way out only from tables other
than the kept one.
"""

VPC_CIDR = "10.30.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "dgraph"
KEPT_TABLE_NAME = "dgraph-outward-rt"
ROUTING_TAG = "Routing"
ROUTING_MARK = "kept-outward"
ROUTING_REF_TAG = "RoutingRef"
ROUTING_REF = "NET-3308"
ROUTING_TAGS = [
    {"Key": ROUTING_TAG, "Value": ROUTING_MARK},
    {"Key": ROUTING_REF_TAG, "Value": ROUTING_REF},
]
KEPT_TABLE_TAGS = [{"Key": "Name", "Value": KEPT_TABLE_NAME}] + ROUTING_TAGS
DEFAULT_ROUTE = "0.0.0.0/0"
# Marks other programs put on the tables they keep; a table carrying one of them is theirs.
OTHER_MARKS = ("Isolation", "Slice")


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _store_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _a_table_that_is_not_the_kept_one(snapshot) -> bool:
    """A table of its own stands in the network and no table in it carries the routing mark."""
    vpcs = _store_vpc_ids(snapshot)
    if not vpcs:
        return False
    standing = False
    for props in _resources(snapshot, "AWS::EC2::RouteTable").values():
        props = props or {}
        if props.get("VpcId") not in vpcs:
            continue
        if _tag(props, ROUTING_TAG) == ROUTING_MARK:
            return False
        if any(_tag(props, mark) for mark in OTHER_MARKS):
            continue  # a table another program keeps
        if _tag(props, "Name"):
            standing = True
    return standing


@distract(
    role="network engineer",
    responsibility="owns routing and connectivity between network segments",
    intent=("the graph-store network's way out is carried by the one table the account keeps "
            "that network's outward routing on, and no table standing beside it in the network "
            "carries a way out"),
    api=on_api("ec2", "DescribeRouteTables", phase="before"),
    release="after_completed",
    predicate=_a_table_that_is_not_the_kept_one,
    resolution=("The outward routing here is carried by the table already kept for it; a table "
                "of your own does not carry it."),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"closed": [], "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]

    tables = ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]
    kept = [t for t in tables if _tag(t, "Name") == KEPT_TABLE_NAME]
    if kept:
        kept_id = sorted(kept, key=lambda t: t["RouteTableId"])[0]["RouteTableId"]
    else:
        kept_id = ec2.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "route-table", "Tags": KEPT_TABLE_TAGS}],
        )["RouteTable"]["RouteTableId"]
    ec2.create_tags(Resources=[kept_id], Tags=KEPT_TABLE_TAGS)

    closed = []
    for table in tables:
        if table["RouteTableId"] == kept_id:
            continue
        if not any(r.get("DestinationCidrBlock") == DEFAULT_ROUTE
                   for r in table.get("Routes") or []):
            continue
        try:
            ec2.delete_route(RouteTableId=table["RouteTableId"],
                             DestinationCidrBlock=DEFAULT_ROUTE)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "InvalidRoute.NotFound":
                raise
        closed.append(table["RouteTableId"])

    return {"route_table": kept_id, "closed": closed,
            "mark": ROUTING_MARK, "reference": ROUTING_REF, "name": KEPT_TABLE_NAME,
            "note": "nothing else carried a way out" if not closed else "way out taken off",
            "fingerprint": [ROUTING_MARK, ROUTING_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
