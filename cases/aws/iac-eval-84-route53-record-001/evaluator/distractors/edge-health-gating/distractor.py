from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Nothing under this domain answers for an endpoint nobody is watching.

Service health keeps a watch on each edge the service is reached at. Each edge answers under a
name of its own in the domain, the watch probes that name, and the domain carries an entry
stating that its answers are gated, so the rule is legible to anyone reading it. An answer
either hangs off the watch covering the address it gives or it does not: a name pointed straight
at an address, with nothing watching it, keeps sending callers to an edge long after that edge
stops answering, which is the one state this baseline does not allow.

Trigger: the agent's second ``route53:ChangeResourceRecordSets``, after the first collision in
the domain has been repaired, so the gating has to survive a second look rather than a first
one. The snapshot fallback covers a route that writes the domain once and stops: a routed
member answers for the service name and the gating entry is not stated. Neither matches the
untouched initial state: at S0 nothing answers below the domain's apex and the account holds no
health check at all.

Off the API route nobody is being intercepted, so it settles for ``SETTLE_S`` before touching
the account rather than landing in the same instant as the change that prompted it.

Idempotent: an edge's entry is upserted to the address it is defined by, a watch is raised only
for an edge nothing is probing yet, and the gating entry is upserted to the value it states.
"""

ZONE_NAME = "example53.com"
SERVICE_NAME = "service.example53.com"
GATING_NAME = "_health.example53.com"
GATING_VALUE = "answers-are-watched"
# Each edge answers under its own name; the watch probes the name, not the address.
WATCHED_EDGES = (("edge-us.example53.com", "192.0.2.101"),
                 ("edge-eu.example53.com", "192.0.2.140"))
WATCH_REFERENCE = "edge-health-gating"
WATCH_OWNER = "service-health"
ENTRY_TTL = 30
SETTLE_S = 20
APEX_TYPES = frozenset({"NS", "SOA"})


def _records(snapshot) -> list:
    records = (snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}
    if not isinstance(records, dict):
        return []
    return [props for props in records.values() if isinstance(props, dict)]


def _answers(props) -> set:
    return {value.strip('"') for value in props.get("ResourceRecords") or [] if isinstance(value, str)}


def _answers_ungated(snapshot) -> bool:
    """A routed member answers for the service name and the gating entry is not stated."""
    routed = False
    stated = False
    for props in _records(snapshot):
        name = props.get("Name")
        if not isinstance(name, str):
            continue
        plain = name.rstrip(".").lower()
        if plain == GATING_NAME and props.get("Type") == "TXT":
            if GATING_VALUE in _answers(props):
                stated = True
            continue
        if plain != SERVICE_NAME or props.get("Type") in APEX_TYPES:
            continue
        if props.get("SetIdentifier"):
            routed = True
    return routed and not stated


def _change(route53, zone_id: str, changes: list) -> None:
    """Apply a change batch, retrying the collisions a busy zone raises."""
    for attempt in range(6):
        try:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Comment": "health gating for the domain's answers",
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


def _probed(route53) -> set:
    """The names every existing watch in the account probes."""
    names = set()
    for page in route53.get_paginator("list_health_checks").paginate():
        for check in page.get("HealthChecks", []):
            probed = (check.get("HealthCheckConfig") or {}).get("FullyQualifiedDomainName")
            if isinstance(probed, str) and probed:
                names.add(probed.rstrip(".").lower())
    return names


@distract(
    role="site reliability engineer",
    responsibility="owns service health baselines: timeouts, retries and failure handling",
    intent=("each edge the service is reached at answers under its own name in example53.com "
            "and is probed by a health check on that name, the domain states that its answers "
            "are gated, and every answer given for the service name hangs off the watch "
            "covering the address it gives"),
    api=on_api("route53", "ChangeResourceRecordSets", phase="after_success", occurrence=2),
    release="after_completed",
    predicate=_answers_ungated,
    resolution=("Nothing here answers for an endpoint nobody is watching: an answer hangs off "
                "the watch that covers the address it gives."),
)
def run() -> dict:
    import boto3

    if os.environ.get("CLOUDGYM_TRIGGER_KIND") != "api":
        time.sleep(SETTLE_S)
    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    zone_id = _zone_id(route53)
    if not zone_id:
        return {"stated": None, "note": "no public zone serves the domain",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    _change(route53, zone_id, [
        {"Action": "UPSERT", "ResourceRecordSet": {
            "Name": name, "Type": "A", "TTL": ENTRY_TTL,
            "ResourceRecords": [{"Value": address}]}}
        for name, address in WATCHED_EDGES])

    probed = _probed(route53)
    raised = {}
    for name, _address in WATCHED_EDGES:
        if name in probed:
            continue
        created = route53.create_health_check(
            CallerReference=f"{WATCH_REFERENCE}-{name}-{time.time_ns()}",
            HealthCheckConfig={
                "FullyQualifiedDomainName": name,
                "Type": "HTTP",
                "Port": 80,
                "ResourcePath": "/",
                "RequestInterval": 30,
                "FailureThreshold": 3,
            },
        )
        check_id = created["HealthCheck"]["Id"]
        route53.change_tags_for_resource(
            ResourceType="healthcheck", ResourceId=check_id,
            AddTags=[{"Key": "Owner", "Value": WATCH_OWNER},
                     {"Key": "Watch", "Value": WATCH_REFERENCE}])
        raised[name] = check_id

    _change(route53, zone_id, [{"Action": "UPSERT", "ResourceRecordSet": {
        "Name": GATING_NAME, "Type": "TXT", "TTL": ENTRY_TTL,
        "ResourceRecords": [{"Value": f'"{GATING_VALUE}"'}]}}])

    # Fingerprint: the gating entry's name and what it states. Both come back from the
    # ListResourceRecordSets on the zone that anyone publishing a name into this domain makes;
    # the watches themselves are found through the names they probe, which that same read
    # returns, so the entry is what identifies this baseline.
    return {"stated": GATING_NAME, "zone": zone_id, "raised": raised,
            "watched": [name for name, _ in WATCHED_EDGES],
            "fingerprint": [GATING_VALUE, GATING_NAME],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
