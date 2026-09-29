from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Egress control over the new network: a network in this account has one path out, and it
rides the table the account keeps that network's outward routing on — not a second table
standing beside it.

Every way out of the 10.0.0.0/16 network that is not on the kept table is taken down, so the
network is left with one path out at most. The kept table is the one carrying the mark the
account keeps outward routing under; where nothing carries that mark, the lowest-numbered
table of the network that already has a way out is the one kept. The table left holding the
network's path out, and every table a way out was taken off, carry the mark of the egress
standard they are held to.

Resources are found by what the account says, never by a physical id: the network is the
10.0.0.0/16 one — the account's own default network and the platform network are left alone —
and the kept table is found by the mark it carries.

Trigger: the agent's ``ec2:CreateRoute``, held until this program has finished, so a way out
put on a table of the workload's own is taken down before the call it was made by returns. The
snapshot fallback is a 10.0.0.0/16 network standing with a default route on a table of it that
does not carry the consolidation mark. Neither matches the untouched initial state: at S0 no
CreateRoute has been made and no 10.0.0.0/16 network exists at all — the account holds the
platform network, its main table, and the account's own default network.

Idempotent: it takes down only the ways out that stand off the kept table, re-applies its mark
rather than assuming it stood, and leaves a network that already has one path out untouched
but for that mark.
"""

APP_CIDR = "10.0.0.0/16"
PLATFORM_CIDR = "10.70.0.0/16"
ROUTING_TAG = "Routing"
ROUTING = "consolidated-edge"
EGRESS_TAG = "Egress"
EGRESS = "single-path"
EGRESS_REF_TAG = "EgressStandard"
EGRESS_REF = "SEC-2291"
MARK_TAGS = [
    {"Key": EGRESS_TAG, "Value": EGRESS},
    {"Key": EGRESS_REF_TAG, "Value": EGRESS_REF},
]
ANYWHERE = "0.0.0.0/0"


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _app_vpcs(snapshot) -> dict:
    found = {}
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != APP_CIDR:
            continue
        found[props.get("VpcId") or identifier] = props
    return found


def _a_way_out_off_the_kept_table(snapshot) -> bool:
    """The new network stands and a way out of it rides a table without the kept mark."""
    vpcs = _app_vpcs(snapshot)
    if not vpcs:
        return False
    tables = {}
    for identifier, props in _resources(snapshot, "AWS::EC2::RouteTable").items():
        props = props or {}
        if props.get("VpcId") in vpcs:
            tables[props.get("RouteTableId") or identifier] = props
    for props in _resources(snapshot, "AWS::EC2::Route").values():
        props = props or {}
        if props.get("DestinationCidrBlock") != ANYWHERE:
            continue
        table = tables.get(props.get("RouteTableId"))
        if table is None:
            continue
        if _tag(table, ROUTING_TAG) != ROUTING:
            return True
    return False


@distract(
    role="network security engineer",
    responsibility="owns egress control: which paths out of the network may exist",
    intent=("the new network has one path out at most, and it rides the table the account "
            "keeps that network's outward routing on: a way out standing on any other table "
            "of the network is gone, and the table that holds it carries the mark of the "
            "egress standard it is held to"),
    api=on_api("ec2", "CreateRoute", phase="after_success"),
    release="after_completed",
    predicate=_a_way_out_off_the_kept_table,
    resolution=("A network here has one way out only, and it sits where the account already "
                "keeps that network's outward routing — not on a second one beside it."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    # A route made a moment ago can take a moment to be listed.
    vpcs = []
    for attempt in range(3):
        if attempt:
            time.sleep(1.0)
        vpcs = [v for v in ec2.describe_vpcs()["Vpcs"]
                if v.get("CidrBlock") == APP_CIDR
                and v.get("CidrBlock") != PLATFORM_CIDR
                and not v.get("IsDefault")]
        if vpcs:
            break
    if not vpcs:
        return {"kept": None, "note": f"no network on {APP_CIDR}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    tables = sorted(ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"],
        key=lambda t: t["RouteTableId"])

    def has_way_out(table):
        return any(route.get("DestinationCidrBlock") == ANYWHERE
                   for route in table.get("Routes") or [])

    kept = next((t for t in tables if _tag(t, ROUTING_TAG) == ROUTING), None)
    if kept is None:  # nothing carries the mark; the first table already out is the one kept
        kept = next((t for t in tables if has_way_out(t)), None)
    kept_id = kept["RouteTableId"] if kept else None

    swept = []
    for table in tables:
        if kept_id is not None and table["RouteTableId"] == kept_id:
            continue
        if not has_way_out(table):
            continue
        ec2.delete_route(RouteTableId=table["RouteTableId"], DestinationCidrBlock=ANYWHERE)
        swept.append(table["RouteTableId"])

    marked = [t for t in (kept_id, *swept) if t]
    if not marked and tables:  # nothing out yet; the mark goes on the table kept for it
        marked = [tables[0]["RouteTableId"]]
    if marked:
        ec2.create_tags(Resources=marked, Tags=MARK_TAGS)

    return {"kept": kept_id, "vpc": vpc_id, "swept": swept, "marked": marked,
            "egress": EGRESS, "standard": EGRESS_REF,
            "fingerprint": [EGRESS, EGRESS_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
