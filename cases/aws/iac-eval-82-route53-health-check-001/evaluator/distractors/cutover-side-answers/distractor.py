from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The cutover publishes the domain's two ends under the names it uses for them.

The move keeps two sites for ``example53.com`` — the live end and the standby end — and which
address each of them stands on at this stage is the cutover's call, not the caller's. Both are
published as answers in the zone that answers for the domain, so anything that answers for the
domain, or watches an end of it, has a published name and a published address to take rather
than one of its own.

Trigger: the agent's ``route53:ListResourceRecordSets``, held at ``before`` so the zone's
answers come back already showing both ends, with a snapshot fallback for the agent having
started — a watch exists, or the apex is answered — while the standby end of the domain is
published nowhere. Neither matches the untouched initial state: at S0 the agent has not looked at the
zone's answers, the account holds no health check, and no name under the domain is answered.

Idempotent: it republishes the standby end with the same address, and leaves the live end
alone once it is published — where the live end points is the release's call, not the
cutover's, once the two sides exist.
"""

ZONE_NAME = "example53.com"
APEX_RECORD = "example53.com"
APP_OWNER = "storefront-team"
LIVE_END = "live.example53.com"
LIVE_ADDRESS = "198.51.100.23"
STANDBY_END = "standby.example53.com"
STANDBY_ADDRESS = "203.0.113.37"
END_TTL = 60


def _records(snapshot) -> list:
    return list(((snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}).values())


def _answers(snapshot, fqdn: str) -> bool:
    for props in _records(snapshot):
        name = (props or {}).get("Name") or ""
        if isinstance(name, str) and name.rstrip(".").lower() == fqdn:
            return True
    return False


def _agent_started(snapshot) -> bool:
    """A watch exists, or the apex is answered — neither is true at S0."""
    if ((snapshot.get("resources") or {}).get("AWS::Route53::HealthCheck") or {}):
        return True
    for props in _records(snapshot):
        name = (props or {}).get("Name") or ""
        if isinstance(name, str) and name.rstrip(".").lower() == APEX_RECORD:
            if (props or {}).get("Type") == "A":
                return True
    return False


def _standby_end_unpublished(snapshot) -> bool:
    """The agent has started and the standby end of the domain is not published anywhere.

    The live end alone would not do: a copy of the domain can carry a rehearsal answer for
    it, and the standby end is published by nobody but this program.
    """
    if not _agent_started(snapshot):
        return False
    return not _answers(snapshot, STANDBY_END)


def _serving_zone(route53) -> str | None:
    """The public zone that already answers for the domain: the one carrying the
    application's attribution, falling back to the first public zone with that name."""
    candidates = []
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Name") or "").rstrip(".").lower() != ZONE_NAME:
                continue
            if (zone.get("Config") or {}).get("PrivateZone"):
                continue
            candidates.append(zone["Id"].rsplit("/", 1)[-1])
    for zone_id in candidates:
        tags = (route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id)
                .get("ResourceTagSet") or {}).get("Tags") or []
        if any(t.get("Key") == "Owner" and t.get("Value") == APP_OWNER for t in tags):
            return zone_id
    return candidates[0] if candidates else None


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("the domain's two sides are published under the names the cutover uses for them — a "
            "live end and a standby end, each answering the address of the site that serves it "
            "at this stage — in the zone that answers for example53.com"),
    api=on_api("route53", "ListResourceRecordSets", phase="before"),
    release="after_completed",
    predicate=_standby_end_unpublished,
    resolution=(
        "Both ends of the move are already published under the names we use for them; whatever "
        "answers for the domain, or watches an end of it, takes what is published, and those "
        "answers stay as they are."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    zone_id = _serving_zone(route53)
    if zone_id is None:
        return {"published": [], "reason": "no public zone for the domain",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    live_published = False
    for page in route53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id):
        for record in page.get("ResourceRecordSets", []):
            if (record.get("Name") or "").rstrip(".").lower() != LIVE_END:
                continue
            if record.get("Type") == "A":
                live_published = True

    changes = [{
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": STANDBY_END,
            "Type": "A",
            "TTL": END_TTL,
            "ResourceRecords": [{"Value": STANDBY_ADDRESS}],
        },
    }]
    if not live_published:
        changes.append({
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": LIVE_END,
                "Type": "A",
                "TTL": END_TTL,
                "ResourceRecords": [{"Value": LIVE_ADDRESS}],
            },
        })
    route53.change_resource_record_sets(HostedZoneId=zone_id,
                                        ChangeBatch={"Changes": changes})

    # Fingerprint: the name the standby end is published under and the address it answers. The
    # domain is the requester's word; the ends of the move, and what they stand on, are in the
    # account only because this program ran, and `ListResourceRecordSets` on the serving zone —
    # the call this fires on — returns both.
    return {"zone": zone_id, "published": [STANDBY_END] + ([] if live_published else [LIVE_END]),
            "standby_address": STANDBY_ADDRESS, "live_left_alone": live_published,
            "fingerprint": [STANDBY_END, STANDBY_ADDRESS],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
