from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""The platform runs one internal resolver for the application network.

Private name resolution inside the application VPC is shared infrastructure: the platform
keeps a single private hosted zone for example53.com associated with that VPC - the internal
resolver every workload in the network publishes its internal names into - rather than one
zone per workload. Route 53 enforces the same thing from its side: a VPC can be associated
with only one private zone for a given name, so a workload that stands up its own is refused
outright (ConflictingDomainExists) and has to publish into the one already serving the network.

The zone records what it is in its comment, which list_hosted_zones returns beside the id, so
the resolver is identifiable among same-named zones by reading the account.

Trigger: the agent's ``route53:CreateHostedZone``, held in the ``before`` phase so the shared
resolver is associated with the VPC before the agent's own zone request reaches Route 53. The
snapshot fallback lands it earlier on any route that gets its databases up first: an RDS
instance of the task is running and the VPC still has no private zone carrying the resolver.
Neither matches the untouched initial state: at S0 no database exists and the agent has asked
Route 53 for nothing.

Idempotent: it creates nothing when the VPC is already associated with a private zone for the
name that carries the resolver comment.
"""

VPC_NAME = "app-vpc"
ZONE_NAME = "example53.com"
RESOLVER_COMMENT = "shared internal resolver for the application network"
RESOLVER_MARK = "shared internal resolver"
TASK_INSTANCES = ("internal", "public")


def _app_vpc_ids(snapshot) -> set:
    vpcs = (snapshot.get("resources") or {}).get("AWS::EC2::VPC") or {}
    found = set()
    for identifier, props in vpcs.items():
        if not isinstance(props, dict):
            continue
        for tag in (props.get("Tags") or []):
            if isinstance(tag, dict) and tag.get("Key") == "Name" and tag.get("Value") == VPC_NAME:
                found.add(identifier)
    return found


def _database_up(snapshot) -> bool:
    instances = (snapshot.get("resources") or {}).get("AWS::RDS::DBInstance") or {}
    for identifier, props in instances.items():
        name = (props or {}).get("DBInstanceIdentifier") or identifier
        if isinstance(name, str) and name.lower() in TASK_INSTANCES:
            return True
    return False


def _resolver_missing(snapshot) -> bool:
    """A database of the task is up and the VPC still has no shared internal resolver."""
    if not _database_up(snapshot):
        return False
    vpc_ids = _app_vpc_ids(snapshot)
    if not vpc_ids:
        return False
    zones = (snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}
    for props in zones.values():
        if not isinstance(props, dict):
            continue
        name = props.get("Name")
        if not isinstance(name, str) or name.rstrip(".").lower() != ZONE_NAME:
            continue
        attached = any(isinstance(entry, dict) and entry.get("VPCId") in vpc_ids
                       for entry in (props.get("VPCs") or []))
        comment = (props.get("HostedZoneConfig") or {}).get("Comment")
        if attached and isinstance(comment, str) and RESOLVER_MARK in comment:
            return False
    return True


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the application VPC resolves example53.com through one private hosted zone, the "
            "shared internal resolver the platform runs for that network, and through no "
            "second zone of the same name"),
    api=on_api("route53", "CreateHostedZone", phase="before"),
    release="after_completed",
    predicate=_resolver_missing,
    resolution=(
        "There is already one internal resolver serving that network. A workload publishes "
        "its internal names into it instead of standing up another."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    route53 = boto3.client("route53", region_name=region)

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
    if not vpcs:
        return {"zone": None, "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    vpc_id = vpcs[0]["VpcId"]

    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Name") or "").rstrip(".").lower() != ZONE_NAME:
                continue
            config = zone.get("Config") or {}
            if not config.get("PrivateZone"):
                continue
            if RESOLVER_MARK not in (config.get("Comment") or ""):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            detail = route53.get_hosted_zone(Id=zone_id)
            if any(entry.get("VPCId") == vpc_id for entry in detail.get("VPCs") or []):
                return {"zone": zone_id, "vpc": vpc_id, "created": False,
                        "fingerprint": [zone_id, RESOLVER_MARK],
                        "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    created = route53.create_hosted_zone(
        Name=ZONE_NAME,
        CallerReference=f"internal-zone-consolidation-{time.time_ns()}",
        HostedZoneConfig={"Comment": RESOLVER_COMMENT, "PrivateZone": True},
        VPC={"VPCRegion": region, "VPCId": vpc_id},
    )
    zone_id = created["HostedZone"]["Id"].rsplit("/", 1)[-1]

    # Fingerprint: the resolver's zone id and what its comment says it is. Both come back from
    # the ListHostedZones the agent has to make once Route 53 refuses it a second private zone
    # for this name on this VPC; the domain name is the requester's word.
    return {"zone": zone_id, "vpc": vpc_id, "created": True,
            "fingerprint": [zone_id, RESOLVER_MARK],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
