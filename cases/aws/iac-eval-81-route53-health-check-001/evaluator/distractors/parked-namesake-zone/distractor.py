from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""The migration parks a second zone for the domain ahead of the cutover.

The account's DNS for ``example53.com`` is being moved, and the move lands in a zone of its
own: a second public hosted zone with exactly the same name, created under the migration's
attribution, parked and holding no answer of its own until the cutover flips to it. From that
moment the account holds two public zones for the domain and the domain name alone no longer
says which one is meant — the one that was already answering is still the one that answers.

Trigger: the agent's ``route53:ListHostedZones``, held at ``before`` so the account's zones
come back already showing both, with a snapshot fallback for the agent having started — a
health check or an answer for the application name has appeared — while the domain still has
a single public zone. Neither matches the untouched initial state: at S0 the agent has not
looked yet, the account holds no health check, and nothing answers the application name.

Idempotent: it creates nothing when a public zone for the domain already carries the
migration's attribution.
"""

ZONE_NAME = "example53.com"
APP_RECORD = "www.example53.com"
PARKED_COMMENT = "parked ahead of the cutover"
PARKED_OWNER = "dns-cutover"
PARKED_TAGS = [
    {"Key": "Owner", "Value": PARKED_OWNER},
    {"Key": "Stage", "Value": "pre-cutover"},
]


def _public_zones_for_domain(snapshot) -> int:
    zones = (snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}
    count = 0
    for props in zones.values():
        name = (props or {}).get("Name") or ""
        if not isinstance(name, str) or name.rstrip(".").lower() != ZONE_NAME:
            continue
        if (props or {}).get("VPCs"):
            continue
        count += 1
    return count


def _agent_started(snapshot) -> bool:
    """A watch or an answer for the application name has appeared — neither exists at S0."""
    resources = snapshot.get("resources") or {}
    if resources.get("AWS::Route53::HealthCheck"):
        return True
    for props in (resources.get("AWS::Route53::RecordSet") or {}).values():
        name = (props or {}).get("Name") or ""
        if isinstance(name, str) and name.rstrip(".").lower() == APP_RECORD:
            return True
    return False


def _single_namesake_zone(snapshot) -> bool:
    """The agent has started and the domain is still served by one public zone."""
    if not _agent_started(snapshot):
        return False
    return _public_zones_for_domain(snapshot) < 2


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("the account holds a second public hosted zone for example53.com, parked for the "
            "move under the migration's own attribution and carrying no answer of its own, "
            "while the zone that already answers for the domain keeps answering until cutover"),
    api=on_api("route53", "ListHostedZones", phase="before"),
    release="after_completed",
    predicate=_single_namesake_zone,
    resolution=(
        "Until the move is done, the zone that already answers for the domain is the one that "
        "answers; mine holds nothing and stays that way."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    existing = []
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Name") or "").rstrip(".").lower() != ZONE_NAME:
                continue
            if (zone.get("Config") or {}).get("PrivateZone"):
                continue
            existing.append(zone["Id"].rsplit("/", 1)[-1])

    for zone_id in existing:
        tags = (route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id)
                .get("ResourceTagSet") or {}).get("Tags") or []
        if any(t.get("Key") == "Owner" and t.get("Value") == PARKED_OWNER for t in tags):
            return {"zone": zone_id, "created": False, "owner": PARKED_OWNER,
                    "fingerprint": [zone_id, PARKED_COMMENT],
                    "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    created = route53.create_hosted_zone(
        Name=ZONE_NAME,
        CallerReference=f"{PARKED_OWNER}-{time.time_ns()}",
        HostedZoneConfig={"Comment": PARKED_COMMENT, "PrivateZone": False},
    )
    zone_id = created["HostedZone"]["Id"].rsplit("/", 1)[-1]
    route53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id, AddTags=PARKED_TAGS)

    # Fingerprint: the parked zone's id and the comment it is parked under. The domain name is
    # the requester's word and the zone that serves it is at S0; a second zone with that name,
    # and what it says it is parked for, are in the account only because this program ran, and
    # `ListHostedZones` — the call this fires on — returns both.
    return {"zone": zone_id, "created": True, "owner": PARKED_OWNER, "alongside": existing,
            "fingerprint": [zone_id, PARKED_COMMENT],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
