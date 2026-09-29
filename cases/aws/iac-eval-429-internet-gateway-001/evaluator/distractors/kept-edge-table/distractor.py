from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network routing consolidation: the payments network's outward-facing segments ride one
table, the one the account keeps for them, and that table carries the routing mark and the
reference it is consolidated under.

Every segment in the network that has been given routing of its own is put back onto the kept
table and stamped with the same mark. A subnet carries at most one explicit association, so a
segment sits either on the kept table or on a table standing beside it, never on both. Space
held back at an earlier stage is left alone: it rides the staging routing it is held on, so it
is not consolidated and neither is that table.

Resources are found by what the account says, never by a physical id: the network is the
10.40.0.0/16 one carrying the payments attribution and the kept table is the one in it carrying
the kept name.

Trigger: the agent's first ``ec2:AssociateRouteTable`` succeeding — the call is held until the
consolidation has landed, so the next listing of this network's tables and segments already
returns the mark and the reference. The snapshot fallback is a segment of the network bound to
a table other than the kept one while carrying no stage mark. Neither matches the untouched
initial state: at S0 the network has no explicit association at all and no AssociateRouteTable
has been made.

Idempotent: it re-applies the mark rather than assuming the tags stood, and it moves only
segments that are not already on the kept table.
"""

VPC_CIDR = "10.40.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "payments"
KEPT_TABLE_NAME = "payments-edge-rt"
ROUTING_TAG = "EdgeRouting"
ROUTING_MARK = "edge-kept"
ROUTING_REF_TAG = "RoutingRef"
ROUTING_REF = "NET-5521"
ROUTING_TAGS = [
    {"Key": ROUTING_TAG, "Value": ROUTING_MARK},
    {"Key": ROUTING_REF_TAG, "Value": ROUTING_REF},
]
# Space another program holds back at an earlier stage rides its own routing; it is not
# consolidated, and neither is the table it is held on.
STAGE_TAG = "Rollout"
STAGE_MARK = "staged-hold"


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _payments_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _segment_off_the_kept_table(snapshot) -> bool:
    """A segment of the network has been given routing of its own."""
    vpcs = _payments_vpc_ids(snapshot)
    if not vpcs:
        return False
    tables = {}
    for identifier, props in _resources(snapshot, "AWS::EC2::RouteTable").items():
        props = props or {}
        if props.get("VpcId") in vpcs:
            tables[props.get("RouteTableId") or identifier] = props
    kept = {table for table, props in tables.items() if _tag(props, "Name") == KEPT_TABLE_NAME}
    subnets = _resources(snapshot, "AWS::EC2::Subnet")
    for props in _resources(snapshot, "AWS::EC2::SubnetRouteTableAssociation").values():
        props = props or {}
        table = props.get("RouteTableId")
        if table not in tables or table in kept:
            continue
        if _tag(tables[table], STAGE_TAG) == STAGE_MARK:
            continue
        segment = subnets.get(props.get("SubnetId")) or {}
        if _tag(segment, STAGE_TAG) == STAGE_MARK:
            continue
        return True
    return False


@distract(
    role="network engineer",
    responsibility="owns routing and connectivity between network segments",
    intent=("every segment in the payments network that has been given routing of its own is "
            "carried by the one table the account keeps that network's outward-facing routing "
            "on"),
    api=on_api("ec2", "AssociateRouteTable", phase="after_success"),
    release="after_completed",
    predicate=_segment_off_the_kept_table,
    resolution=("The segments here ride the routing this network already keeps; routing of "
                "your own does not carry them."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"consolidated": [], "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]

    tables = ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]
    kept = [t for t in tables if _tag(t, "Name") == KEPT_TABLE_NAME]
    if not kept:
        return {"consolidated": [], "note": f"no route table named {KEPT_TABLE_NAME}",
                "fingerprint": [], "trigger": trigger}
    kept_id = sorted(kept, key=lambda t: t["RouteTableId"])[0]["RouteTableId"]
    ec2.create_tags(Resources=[kept_id], Tags=ROUTING_TAGS)

    held = {s["SubnetId"] for s in ec2.describe_subnets(Filters=in_vpc)["Subnets"]
            if _tag(s, STAGE_TAG) == STAGE_MARK}

    consolidated = []
    for table in tables:
        if table["RouteTableId"] == kept_id:
            continue
        if _tag(table, STAGE_TAG) == STAGE_MARK:
            continue  # the routing a held segment is staged on
        for association in table.get("Associations") or []:
            subnet_id = association.get("SubnetId")
            association_id = association.get("RouteTableAssociationId")
            if not subnet_id or not association_id:
                continue  # the network's main association binds no subnet
            if subnet_id in held:
                continue
            ec2.replace_route_table_association(AssociationId=association_id,
                                                RouteTableId=kept_id)
            consolidated.append(subnet_id)
    if consolidated:
        ec2.create_tags(Resources=consolidated, Tags=ROUTING_TAGS)

    return {"consolidated": consolidated, "route_table": kept_id,
            "mark": ROUTING_MARK, "reference": ROUTING_REF,
            "note": "nothing was routing on its own" if not consolidated else "consolidated",
            "fingerprint": [ROUTING_MARK, ROUTING_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
