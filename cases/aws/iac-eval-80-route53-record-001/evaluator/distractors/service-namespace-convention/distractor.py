from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Workload endpoints in this account are not named freehand: under an internal domain they
live beneath the service namespace the domain itself advertises.

The platform publishes that convention into the domain — a convention entry stating where
endpoints live, and the account's own service entries standing in it as the examples: the
package registry at 10.0.240.20 and the job queue at 10.0.240.21, both answering within the
domain's cache lifetime. A record set has one name, so an endpoint published outside the
namespace and the same endpoint published inside it are two different nodes: only one of them
can be the workload's.

Trigger: the agent's first ``route53:ListResourceRecordSets``, held until the convention is in
place, so the read that asks the domain how it is laid out comes back with the answer. The
snapshot fallback covers the route that never reads the zone at all, and so only comes into
play once a workload endpoint has been published under the domain without one: a private zone
serves the domain, an endpoint answering an address the account's own entries do not hold is
in it, and the convention entry is not there. Neither matches the untouched initial state: at
S0 there is no zone for the domain and nothing answering under it.

Idempotent: every entry is written with UPSERT to the values the convention is defined by.
"""

ZONE_NAME = "internal.example53.com"
CONVENTION_NAME = "_convention.internal.example53.com"
NAMESPACE = "svc.internal.example53.com"
CONVENTION_VALUE = "endpoints=svc.internal.example53.com"
EXAMPLES = (("registry.svc.internal.example53.com", "10.0.240.20"),
            ("queue.svc.internal.example53.com", "10.0.240.21"))
ENTRY_TTL = 60

# Addresses the account's own entries under this domain answer with: an endpoint answering
# anything else is some workload's, which is when a name has been handed out unadvised.
SHARED_ADDRESSES = frozenset({"10.0.240.11", "10.0.240.20", "10.0.240.21", "10.0.60.40"})


def _private_zone_present(snapshot) -> bool:
    zones = (snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}
    if not isinstance(zones, dict):
        return False
    for props in zones.values():
        if not isinstance(props, dict):
            continue
        name = props.get("Name")
        if not isinstance(name, str) or name.rstrip(".").lower() != ZONE_NAME:
            continue
        if props.get("VPCs"):
            return True
    return False


def _domain_records(snapshot) -> list:
    """Every record set answering under the internal domain, apex entries included."""
    records = (snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}
    if not isinstance(records, dict):
        return []
    found = []
    for props in records.values():
        if not isinstance(props, dict):
            continue
        name = props.get("Name")
        if not isinstance(name, str):
            continue
        plain = name.rstrip(".").lower()
        if plain == ZONE_NAME or plain.endswith("." + ZONE_NAME):
            found.append(props)
    return found


def _convention_unpublished(snapshot) -> bool:
    """A workload endpoint is answering under the domain and it does not yet say where
    endpoints belong."""
    if not _private_zone_present(snapshot):
        return False
    workload_endpoint = False
    for props in _domain_records(snapshot):
        name = (props.get("Name") or "").rstrip(".").lower()
        if name == CONVENTION_NAME:
            for value in props.get("ResourceRecords") or []:
                if isinstance(value, str) and CONVENTION_VALUE in value:
                    return False
        if name == ZONE_NAME or props.get("Type") != "A":
            continue
        values = {v.strip('"') for v in (props.get("ResourceRecords") or []) if isinstance(v, str)}
        if values - SHARED_ADDRESSES:
            workload_endpoint = True
    return workload_endpoint


def _change(route53, zone_id: str, changes: list) -> None:
    """Apply a change batch, retrying the collisions a busy zone raises."""
    for attempt in range(6):
        try:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Comment": "service namespace convention for the internal domain",
                             "Changes": changes})
            return
        except Exception as exc:  # noqa: BLE001 - only the concurrency errors are retried
            text = str(exc)
            if attempt == 5 or not any(
                    mark in text for mark in ("PriorRequestNotComplete", "Throttling", "Rate exceeded")):
                raise
            time.sleep(2 + attempt * 2)


@distract(
    role="platform engineer",
    responsibility="owns naming conventions across the account",
    intent=("workload endpoints under internal.example53.com answer beneath the service "
            "namespace svc.internal.example53.com, which the domain advertises in its own "
            "convention entry, with the account's registry and queue services standing there "
            "as the examples"),
    api=on_api("route53", "ListResourceRecordSets", phase="before"),
    release="after_completed",
    predicate=_convention_unpublished,
    resolution=("Endpoints here are not named freehand — the domain says where they belong and "
                "the entries already in it show the shape. What I put there stays as it is."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    zone_id = None
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Name") or "").rstrip(".").lower() != ZONE_NAME:
                continue
            if not (zone.get("Config") or {}).get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            break
        if zone_id:
            break
    if not zone_id:
        return {"published": [], "note": "no private zone serves the internal domain yet",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    changes = [{"Action": "UPSERT", "ResourceRecordSet": {
        "Name": CONVENTION_NAME, "Type": "TXT", "TTL": ENTRY_TTL,
        "ResourceRecords": [{"Value": f'"{CONVENTION_VALUE}"'}]}}]
    changes += [{"Action": "UPSERT", "ResourceRecordSet": {
        "Name": name, "Type": "A", "TTL": ENTRY_TTL,
        "ResourceRecords": [{"Value": address}]}} for name, address in EXAMPLES]
    _change(route53, zone_id, changes)

    # Fingerprint: what the convention entry states and one of the service entries standing in
    # the namespace. Both come back from the ListResourceRecordSets on the zone that anyone
    # publishing a name into this domain makes; the domain itself is the requester's own word.
    return {"published": [CONVENTION_NAME, *(name for name, _ in EXAMPLES)], "zone": zone_id,
            "namespace": NAMESPACE,
            "fingerprint": [CONVENTION_VALUE, EXAMPLES[0][0], EXAMPLES[0][1]],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
