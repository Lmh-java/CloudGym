from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Platform consolidation of outward routing: a network in this account routes outward on the
one table the account keeps for it, under the mark and the reference that routing is kept
under, and not on a second table of its own.

The kept table is stood up in the new 10.0.0.0/16 network as soon as that network exists,
carrying the consolidation mark and the reference it is kept under. A way out already standing
on another table of that network is moved onto the kept one, so the network keeps one way out
and it is the kept table's; where the gateway that way out points at is no longer that
network's to route through, the move is left undone and the table stands empty, waiting for
the network's way out to be put on it.

Resources are found by what the account says, never by a physical id: the network is the
10.0.0.0/16 one — the account's own default network and the platform network are left alone —
and the kept table is the one in it carrying the consolidation mark.

Trigger: the agent's ``ec2:CreateVpc``, held until this program has finished, so the kept
table already stands in the network before anything else is put in it. The snapshot fallback
is a 10.0.0.0/16 network standing in the account with no table of it carrying the
consolidation mark. Neither matches the untouched initial state: at S0 no CreateVpc has been
made and no 10.0.0.0/16 network exists at all — the account holds the platform network, its
main table, and the account's own default network.

Idempotent: it stands the kept table up only when no table of the network carries the mark,
re-applies the mark and the reference rather than assuming they stood, and moves a way out
only while one stands on a table that is not the kept one.
"""

APP_CIDR = "10.0.0.0/16"
PLATFORM_CIDR = "10.70.0.0/16"
TABLE_NAME = "consolidated-edge-rt"
ROUTING_TAG = "Routing"
ROUTING = "consolidated-edge"
ROUTING_REF_TAG = "RoutingRef"
ROUTING_REF = "NET-4417"
TABLE_TAGS = [
    {"Key": "Name", "Value": TABLE_NAME},
    {"Key": ROUTING_TAG, "Value": ROUTING},
    {"Key": ROUTING_REF_TAG, "Value": ROUTING_REF},
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


def _a_network_without_the_kept_table(snapshot) -> bool:
    """The new network stands and nothing in it carries the consolidation mark yet."""
    vpcs = _app_vpcs(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::EC2::RouteTable").values():
        props = props or {}
        if props.get("VpcId") not in vpcs:
            continue
        if _tag(props, ROUTING_TAG) == ROUTING and _tag(props, ROUTING_REF_TAG) == ROUTING_REF:
            return False
    return True


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the new network's outward routing is consolidated on the one table the account "
            "keeps for it: that table stands in the network under the consolidation mark and "
            "the reference it is kept under, and carries the network's way out rather than a "
            "second table of the workload's own"),
    api=on_api("ec2", "CreateVpc", phase="after_success"),
    release="after_completed",
    predicate=_a_network_without_the_kept_table,
    resolution=("This network's outward routing is kept on the table already standing here; "
                "put the way out on that one rather than on a table of your own."),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    # A network that has just been created can take a moment to be listed.
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
        return {"table": None, "note": f"no network on {APP_CIDR}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    kept = next((t for t in sorted(tables, key=lambda t: t["RouteTableId"])
                 if _tag(t, ROUTING_TAG) == ROUTING
                 and _tag(t, ROUTING_REF_TAG) == ROUTING_REF), None)
    if kept is None:
        table_id = ec2.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "route-table", "Tags": TABLE_TAGS}],
        )["RouteTable"]["RouteTableId"]
    else:
        table_id = kept["RouteTableId"]
    ec2.create_tags(Resources=[table_id], Tags=TABLE_TAGS)

    moved = []
    for table in tables:
        if table["RouteTableId"] == table_id:
            continue
        for route in table.get("Routes") or []:
            if route.get("DestinationCidrBlock") != ANYWHERE:
                continue
            gateway_id = route.get("GatewayId")
            ec2.delete_route(RouteTableId=table["RouteTableId"],
                             DestinationCidrBlock=ANYWHERE)
            if not gateway_id:
                continue
            try:
                ec2.create_route(RouteTableId=table_id, DestinationCidrBlock=ANYWHERE,
                                 GatewayId=gateway_id)
            except Exception as error:  # the gateway is no longer this network's to use,
                tolerated = ("NotAttached", "InvalidGatewayID",  # or the way out already stands
                             "RouteAlreadyExists")
                if not any(reason in str(error) for reason in tolerated):
                    raise
                continue
            moved.append(table["RouteTableId"])

    return {"table": table_id, "vpc": vpc_id, "moved_from": moved, "routing": ROUTING,
            "reference": ROUTING_REF, "name": TABLE_NAME,
            "fingerprint": [ROUTING, ROUTING_REF], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
