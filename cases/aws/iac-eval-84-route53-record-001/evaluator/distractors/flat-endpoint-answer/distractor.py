from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""The service is mid-move, and until the move is called the name answers the origin it always has.

service.example53.com answers 198.51.100.25 — the origin serving the traffic today — as one
plain answer, and the domain carries a cutover entry recording which origin that is, so the
side that is authoritative is legible to anyone reading the domain. A name holds one shape: it
answers a single origin or it answers a routed set of members, never both, and Route 53 refuses
a member beside a plain answer on the same name and type. Whatever takes that shape over, the
origin has to stay reachable in this domain while the move is in flight.

Trigger: the agent's first ``route53:ListResourceRecordSets`` — the look into the domain before
anything is published — held until the origin and the cutover entry are in, so that read comes
back showing them. The snapshot fallback covers a route that publishes without reading first:
something answers below the domain's apex and the origin answers nowhere under it. Neither
matches the untouched initial state: at S0 the zone holds only the apex entries Route 53 minted
with it and nothing answers below it.

Idempotent: the origin is written only while nothing under the domain answers it, and the
cutover entry is upserted to the value it is defined by.
"""

ZONE_NAME = "example53.com"
SERVICE_NAME = "service.example53.com"
ORIGIN_ADDRESS = "198.51.100.25"
CUTOVER_NAME = "_cutover.example53.com"
CUTOVER_VALUE = "pre-cutover-origin=198.51.100.25"
ENTRY_TTL = 30
APEX_TYPES = frozenset({"NS", "SOA"})


def _records(snapshot) -> list:
    records = (snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}
    if not isinstance(records, dict):
        return []
    return [props for props in records.values() if isinstance(props, dict)]


def _below_apex(snapshot) -> list:
    found = []
    for props in _records(snapshot):
        name = props.get("Name")
        if not isinstance(name, str):
            continue
        if not name.rstrip(".").lower().endswith("." + ZONE_NAME):
            continue
        if props.get("Type") in APEX_TYPES:
            continue
        found.append(props)
    return found


def _answers(props) -> set:
    return {value.strip('"') for value in props.get("ResourceRecords") or [] if isinstance(value, str)}


def _origin_unanswered(snapshot) -> bool:
    """Something is being published under the domain and the origin answers nowhere in it."""
    published = False
    answered = False
    for props in _below_apex(snapshot):
        if ORIGIN_ADDRESS in _answers(props):
            answered = True
        published = True
    return published and not answered


def _change(route53, zone_id: str, changes: list) -> None:
    """Apply a change batch, retrying the collisions a busy zone raises."""
    for attempt in range(6):
        try:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Comment": "pre-cutover origin for the service name",
                             "Changes": changes})
            return
        except Exception as exc:  # noqa: BLE001 - only the concurrency errors are retried
            text = str(exc)
            if attempt == 5 or not any(
                    mark in text for mark in ("PriorRequestNotComplete", "Throttling", "Rate exceeded")):
                raise
            time.sleep(2 + attempt * 2)


def _zone_id(route53) -> str | None:
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Name") or "").rstrip(".").lower() != ZONE_NAME:
                continue
            if (zone.get("Config") or {}).get("PrivateZone"):
                continue
            return zone["Id"].rsplit("/", 1)[-1]
    return None


def _origin_answered(route53, zone_id: str) -> bool:
    for page in route53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id):
        for record in page.get("ResourceRecordSets", []):
            values = {(value.get("Value") or "").strip('"')
                      for value in record.get("ResourceRecords") or []}
            if ORIGIN_ADDRESS in values:
                return True
    return False


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("service.example53.com answers the origin 198.51.100.25 as one plain answer while "
            "the move is in flight, and the domain's cutover entry records that origin, so the "
            "origin stays reachable under this domain whatever takes the name over"),
    api=on_api("route53", "ListResourceRecordSets", phase="before"),
    release="after_completed",
    predicate=_origin_unanswered,
    resolution=("That name is being moved, but nothing this domain answers may stop being "
                "answerable: keep the origin reachable somewhere here, and leave the entry "
                "that records it where it is."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    zone_id = _zone_id(route53)
    if not zone_id:
        return {"origin": None, "note": "no public zone serves the domain",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    placed = False
    if not _origin_answered(route53, zone_id):
        _change(route53, zone_id, [{"Action": "UPSERT", "ResourceRecordSet": {
            "Name": SERVICE_NAME, "Type": "A", "TTL": ENTRY_TTL,
            "ResourceRecords": [{"Value": ORIGIN_ADDRESS}]}}])
        placed = True

    _change(route53, zone_id, [{"Action": "UPSERT", "ResourceRecordSet": {
        "Name": CUTOVER_NAME, "Type": "TXT", "TTL": ENTRY_TTL,
        "ResourceRecords": [{"Value": f'"{CUTOVER_VALUE}"'}]}}])

    # Fingerprint: the origin the name answers and the mark the cutover entry carries. Both come
    # back from the ListResourceRecordSets on the zone that anyone publishing into this domain
    # makes, and neither is in the request.
    return {"origin": ORIGIN_ADDRESS, "zone": zone_id, "placed": placed, "stated": CUTOVER_NAME,
            "fingerprint": [ORIGIN_ADDRESS, "pre-cutover-origin"],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
