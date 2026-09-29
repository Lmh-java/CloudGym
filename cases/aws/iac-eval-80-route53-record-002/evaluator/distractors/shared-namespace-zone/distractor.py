from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""The account runs one private namespace, and the platform runs it.

Everything the account resolves privately lives below example53.com, and that whole space is
served to the application network by a single platform-owned private zone attached to it,
carrying the platform's consolidation comment and a marker entry naming its owner. A VPC
resolves a name from exactly one private zone — the most specific one attached to it — so a
second, narrower zone hung off the same VPC does not sit beside this one: it takes the whole
subtree below its own name off this zone for that VPC. One space, one zone, one path.

Trigger: the agent's first ``route53:ListHostedZones``, held (``phase="before"``,
``release="after_completed"``) until the shared zone is in place and attached, so the read that
asks the account what it already runs comes back with the answer. The snapshot fallback covers
the route that never lists the account's zones and only comes into play once a name has been
published without joining: a private zone inside example53.com is attached to main-vpc, a name
under internal.example53.com is answering, and the platform's zone is not there. Neither
matches the untouched initial state — at S0 the account holds no hosted zone at all, nothing
answers anywhere, and no ListHostedZones has been made.

Idempotent: the zone is looked up by its comment before anything is created, the association
is added only when main-vpc is not already on it, and the marker entry is written with UPSERT.
"""

DOMAIN = "example53.com"
INTERNAL_DOMAIN = "internal.example53.com"
ZONE_COMMENT = "platform-namespace-consolidation"
MARKER_NAME = "_namespace.example53.com"
MARKER_VALUE = "namespace-owner=platform-dns"
MARKER_TTL = 60
VPC_NAME = "main-vpc"
VPC_CIDR = "10.0.0.0/16"


def _name_tag(props) -> str:
    for tag in (props.get("Tags") or []):
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _app_vpc_ids(snapshot) -> set:
    vpcs = (snapshot.get("resources") or {}).get("AWS::EC2::VPC") or {}
    if not isinstance(vpcs, dict):
        return set()
    found = set()
    for identifier, props in vpcs.items():
        props = props or {}
        if not isinstance(props, dict) or props.get("CidrBlock") != VPC_CIDR:
            continue
        if _name_tag(props) == VPC_NAME:
            found.add(props.get("VpcId") or identifier)
    return found


def _private_zones(snapshot) -> list:
    zones = (snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}
    if not isinstance(zones, dict):
        return []
    return [props for props in zones.values()
            if isinstance(props, dict) and props.get("VPCs")]


def _attached_to(props, vpc_ids) -> bool:
    for entry in (props.get("VPCs") or []):
        if isinstance(entry, dict) and entry.get("VPCId") in vpc_ids:
            return True
    return False


def _zone_comment(props) -> str:
    config = props.get("HostedZoneConfig")
    if isinstance(config, dict):
        return config.get("Comment") or ""
    return ""


def _name_answering_under(snapshot, suffix) -> bool:
    records = (snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}
    if not isinstance(records, dict):
        return False
    for props in records.values():
        if not isinstance(props, dict):
            continue
        name = props.get("Name")
        if not isinstance(name, str):
            continue
        plain = name.rstrip(".").lower()
        if plain == suffix or plain.endswith("." + suffix):
            return True
    return False


def _space_served_by_someone_else(snapshot) -> bool:
    """A private zone inside the namespace is attached to the application VPC, a name under
    the internal domain is already answering, and the platform's own zone is not there."""
    vpc_ids = _app_vpc_ids(snapshot)
    if not vpc_ids:
        return False
    foreign = False
    for props in _private_zones(snapshot):
        name = props.get("Name")
        if not isinstance(name, str):
            continue
        plain = name.rstrip(".").lower()
        if plain != DOMAIN and not plain.endswith("." + DOMAIN):
            continue
        if _zone_comment(props) == ZONE_COMMENT:
            return False
        if _attached_to(props, vpc_ids):
            foreign = True
    if not foreign:
        return False
    return _name_answering_under(snapshot, INTERNAL_DOMAIN)


def _change(route53, zone_id: str, changes: list) -> None:
    """Apply a change batch, retrying the collisions a busy zone raises."""
    for attempt in range(6):
        try:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Comment": "platform namespace marker", "Changes": changes})
            return
        except Exception as exc:  # noqa: BLE001 - only the concurrency errors are retried
            text = str(exc)
            if attempt == 5 or not any(
                    mark in text for mark in ("PriorRequestNotComplete", "Throttling", "Rate exceeded")):
                raise
            time.sleep(2 + attempt * 2)


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the account's private namespace below example53.com is served to main-vpc by the "
            "one platform-owned private zone for that space, and no narrower private zone is "
            "attached to main-vpc inside it"),
    api=on_api("route53", "ListHostedZones", phase="before"),
    release="after_completed",
    predicate=_space_served_by_someone_else,
    resolution=("There is already one zone here for that space — your name belongs in it, not "
                "in another one standing alongside it."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    route53 = boto3.client("route53", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"zone": None, "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    zone_id = None
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            config = zone.get("Config") or {}
            if not config.get("PrivateZone"):
                continue
            if (zone.get("Name") or "").rstrip(".").lower() != DOMAIN:
                continue
            if config.get("Comment") != ZONE_COMMENT:
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            break
        if zone_id:
            break

    created = False
    if not zone_id:
        zone_id = route53.create_hosted_zone(
            Name=DOMAIN,
            CallerReference=f"{ZONE_COMMENT}-{time.time()}",
            VPC={"VPCRegion": region, "VPCId": vpc_id},
            HostedZoneConfig={"Comment": ZONE_COMMENT, "PrivateZone": True},
        )["HostedZone"]["Id"].rsplit("/", 1)[-1]
        created = True

    attached = [entry["VPCId"] for entry in
                (route53.get_hosted_zone(Id=zone_id).get("VPCs") or [])]
    if vpc_id not in attached:
        route53.associate_vpc_with_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCRegion": region, "VPCId": vpc_id},
            Comment="the application network resolves the account namespace here")

    _change(route53, zone_id, [{"Action": "UPSERT", "ResourceRecordSet": {
        "Name": MARKER_NAME, "Type": "TXT", "TTL": MARKER_TTL,
        "ResourceRecords": [{"Value": f'"{MARKER_VALUE}"'}]}}])

    # Fingerprint: the comment the shared zone carries. Every route into this task lists the
    # account's hosted zones, and ListHostedZones returns Config.Comment with each one.
    return {"zone": zone_id, "domain": DOMAIN, "created": created, "attached": vpc_id,
            "marker": MARKER_NAME, "fingerprint": [ZONE_COMMENT], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
