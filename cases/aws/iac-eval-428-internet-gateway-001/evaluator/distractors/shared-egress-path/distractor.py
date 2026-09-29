from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Shared egress path: a network gets one way out, provided once, and one table
that uses it. The network engineer keeps `net-shared-igw` attached to `app-vpc`
and `net-shared-public-rt` as the table whose default route leaves through it;
segments that need the internet are associated with that table instead of each
workload attaching its own gateway (AWS admits exactly one attached internet
gateway per VPC) and standing up its own public table (a subnet has exactly one
route-table association).

The program only creates or completes its own two resources — it never edits,
re-associates or deletes anyone else's route table, and it never associates a
subnet, because which segments are public is their owner's call. So the agent
has to associate its new subnets with the shared table itself.

Fires on the agent's CreateInternetGateway, held before the call, so the shared
gateway is attached before the agent's own gateway could be (the agent's attach
then fails with Resource.AlreadyAssociated, and this is always before any
0.0.0.0/0 route of its own can exist, since a route needs a gateway). Snapshot
fallback for a route that never calls it: app-vpc has a route table beyond its
main one and nothing in the VPC routes to 0.0.0.0/0 yet. Never fires on the
untouched initial state: at S0 app-vpc has exactly one route table (its main
one) and no internet gateway exists at all. Idempotent: the gateway and the
table are found by their Name tag and completed, never duplicated.
"""

VPC_NAME = "app-vpc"
IGW_NAME = "net-shared-igw"
TABLE_NAME = "net-shared-public-rt"
DEFAULT_ROUTE = "0.0.0.0/0"
OWNER = "network-platform"


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


def _progress_without_shared_path(snapshot) -> bool:
    vpcs = _app_vpc_ids(snapshot)
    if not vpcs:
        return False
    tables = set()
    for key, props in _resources(snapshot, "AWS::EC2::RouteTable"):
        if props.get("VpcId") in vpcs:
            tables.add(props.get("RouteTableId") or key)
    if len(tables) < 2:
        return False
    for _, props in _resources(snapshot, "AWS::EC2::Route"):
        if props.get("RouteTableId") in tables and props.get("DestinationCidrBlock") == DEFAULT_ROUTE:
            return False
    return True


def _name_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "Owner", "Value": OWNER}]


@distract(
    role="network engineer",
    responsibility="owns routing and connectivity between network segments",
    intent="app-vpc has exactly one way out — the shared gateway net-shared-igw attached to it — and exactly one table that uses it, net-shared-public-rt with a 0.0.0.0/0 route through that gateway, which the segments needing the internet are associated with",
    api=on_api("ec2", "CreateInternetGateway", phase="before"),
    release="after_completed",
    predicate=_progress_without_shared_path,
    resolution="The way out of this network is provided once and shared; segments that need it attach to what is already there rather than standing up their own.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
    if not vpcs:
        return {"vpc": None, "changed": [], "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    vpc_id = vpcs[0]["VpcId"]
    changed = []
    fingerprint = []

    # The shared gateway: ours by Name tag if it exists, otherwise created and attached.
    # If some other gateway already occupies the VPC's single attachment slot, adopt it
    # rather than fighting over it — the table below then routes through what is there.
    mine = ec2.describe_internet_gateways(
        Filters=[{"Name": "tag:Name", "Values": [IGW_NAME]}])["InternetGateways"]
    if mine:
        igw_id = mine[0]["InternetGatewayId"]
        fingerprint.append(IGW_NAME)
        if not [a for a in mine[0].get("Attachments") or [] if a.get("VpcId") == vpc_id]:
            try:
                ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                changed.append(f"attached {igw_id}")
            except Exception:
                pass
    else:
        attached = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
        if attached:
            igw_id = attached[0]["InternetGatewayId"]
        else:
            igw_id = ec2.create_internet_gateway(TagSpecifications=[
                {"ResourceType": "internet-gateway", "Tags": _name_tags(IGW_NAME)}
            ])["InternetGateway"]["InternetGatewayId"]
            ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            changed.append(f"created {igw_id}")
            fingerprint.append(IGW_NAME)

    # The shared public table, with its default route through that gateway.
    tables = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "tag:Name", "Values": [TABLE_NAME]},
    ])["RouteTables"]
    if tables:
        table = tables[0]
    else:
        table = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[
            {"ResourceType": "route-table", "Tags": _name_tags(TABLE_NAME)}
        ])["RouteTable"]
        changed.append(f"created {table['RouteTableId']}")
    table_id = table["RouteTableId"]
    fingerprint.append(TABLE_NAME)

    default = [r for r in table.get("Routes") or []
               if r.get("DestinationCidrBlock") == DEFAULT_ROUTE]
    if not default:
        try:
            ec2.create_route(RouteTableId=table_id, DestinationCidrBlock=DEFAULT_ROUTE,
                             GatewayId=igw_id)
            changed.append(f"routed {table_id} -> {igw_id}")
        except Exception:
            ec2.replace_route(RouteTableId=table_id, DestinationCidrBlock=DEFAULT_ROUTE,
                              GatewayId=igw_id)
            changed.append(f"rerouted {table_id} -> {igw_id}")
    elif default[0].get("GatewayId") != igw_id:
        ec2.replace_route(RouteTableId=table_id, DestinationCidrBlock=DEFAULT_ROUTE,
                          GatewayId=igw_id)
        changed.append(f"rerouted {table_id} -> {igw_id}")

    return {"vpc": vpc_id, "gateway": igw_id, "table": table_id, "changed": changed,
            "fingerprint": fingerprint,
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
