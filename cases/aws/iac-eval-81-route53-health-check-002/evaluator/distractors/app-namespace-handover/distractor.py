from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Naming hands the application namespace over to a zone of its own.

Record ownership under this account's domains is kept one namespace at a time: the names under
``app.example53.com`` are answered by a public hosted zone raised for that namespace, and the
domain's own zone stops answering under it — it carries the handover to the new zone and nothing
else below it. From that moment a query for a name under the namespace is sent to the zone the
namespace was handed to, and an answer left in the zone above is never reached.

Trigger: the agent's ``route53:ListHostedZones``, held at ``before`` so the account's zones come
back already showing the delegated zone and the handover, with a snapshot fallback for the agent
having started — a watch exists, or a name under the namespace is answered — while the namespace
still has no zone of its own. Neither matches the untouched initial state: at S0 the agent has
not looked yet, the account holds no health check, and no name under the domain is answered.

Idempotent: it raises no second zone once the namespace has one, republishes the same handover,
and carries any answer it finds left under the namespace in the zone above over to the delegated
zone rather than dropping it.
"""

DOMAIN = "example53.com"
NAMESPACE = "app.example53.com"
HANDOVER_COMMENT = "namespace handed over to its own zone"
HANDOVER_OWNER = "dns-naming"
HANDOVER_TAGS = [
    {"Key": "Owner", "Value": HANDOVER_OWNER},
    {"Key": "Namespace", "Value": "app-handover"},
]
HANDOVER_TTL = 172800
APP_OWNER = "orders-team"


def _under_namespace(name) -> bool:
    if not isinstance(name, str):
        return False
    name = name.rstrip(".").lower()
    return name == NAMESPACE or name.endswith("." + NAMESPACE)


def _agent_started(snapshot) -> bool:
    """A watch exists, or a name under the namespace is answered — neither holds at S0."""
    resources = snapshot.get("resources") or {}
    if resources.get("AWS::Route53::HealthCheck"):
        return True
    for props in (resources.get("AWS::Route53::RecordSet") or {}).values():
        if _under_namespace((props or {}).get("Name")):
            return True
    return False


def _namespace_zones(snapshot) -> int:
    count = 0
    for props in ((snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}).values():
        name = (props or {}).get("Name") or ""
        if not isinstance(name, str) or name.rstrip(".").lower() != NAMESPACE:
            continue
        if (props or {}).get("VPCs"):
            continue
        count += 1
    return count


def _namespace_not_handed_over(snapshot) -> bool:
    """The agent has started and the namespace still has no zone of its own."""
    if not _agent_started(snapshot):
        return False
    return _namespace_zones(snapshot) < 1


def _public_zones_named(route53, zone_name: str) -> list[str]:
    found = []
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Config") or {}).get("PrivateZone"):
                continue
            if (zone.get("Name") or "").rstrip(".").lower() != zone_name:
                continue
            found.append(zone["Id"].rsplit("/", 1)[-1])
    return found


def _domain_zone(route53) -> str | None:
    """The zone that answers for the domain: the one carrying the application's attribution,
    falling back to the first public zone with that name."""
    candidates = _public_zones_named(route53, DOMAIN)
    for zone_id in candidates:
        tags = (route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id)
                .get("ResourceTagSet") or {}).get("Tags") or []
        if any(t.get("Key") == "Owner" and t.get("Value") == APP_OWNER for t in tags):
            return zone_id
    return candidates[0] if candidates else None


@distract(
    role="network engineer",
    responsibility="owns naming and record ownership under the account's domains",
    intent=("names under app.example53.com are answered by the zone the account has handed that "
            "namespace to — a public hosted zone of its own, raised under naming's attribution "
            "and carrying the comment it was handed over with — and the domain's zone carries "
            "the handover to it and no answer of its own under that namespace"),
    api=on_api("route53", "ListHostedZones", phase="before"),
    release="after_completed",
    predicate=_namespace_not_handed_over,
    resolution=(
        "Names in that part of the domain are answered where the account hands them to; what "
        "sits above carries only the handover."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    existing = _public_zones_named(route53, NAMESPACE)
    if existing:
        zone_id, created = existing[0], False
    else:
        made = route53.create_hosted_zone(
            Name=NAMESPACE,
            CallerReference=f"{HANDOVER_OWNER}-{time.time_ns()}",
            HostedZoneConfig={"Comment": HANDOVER_COMMENT, "PrivateZone": False},
        )
        zone_id, created = made["HostedZone"]["Id"].rsplit("/", 1)[-1], True
        route53.change_tags_for_resource(
            ResourceType="hostedzone", ResourceId=zone_id, AddTags=HANDOVER_TAGS)

    name_servers = (route53.get_hosted_zone(Id=zone_id).get("DelegationSet") or {}).get(
        "NameServers") or []

    domain_zone = _domain_zone(route53)
    carried = []
    if domain_zone is not None and name_servers:
        route53.change_resource_record_sets(
            HostedZoneId=domain_zone,
            ChangeBatch={"Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": NAMESPACE,
                    "Type": "NS",
                    "TTL": HANDOVER_TTL,
                    "ResourceRecords": [{"Value": server} for server in name_servers],
                },
            }]})

        # Anything already answered under the namespace in the zone above is carried over to
        # the zone the namespace was handed to, then cleared from above: the handover leaves
        # the domain's zone with the handover record and nothing else below it.
        shadowed = []
        for page in route53.get_paginator("list_resource_record_sets").paginate(
                HostedZoneId=domain_zone):
            for record in page.get("ResourceRecordSets", []):
                name = (record.get("Name") or "").rstrip(".").lower()
                if not _under_namespace(name):
                    continue
                if record.get("Type") in {"NS", "SOA"} and name == NAMESPACE:
                    continue
                shadowed.append(record)
        if shadowed:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Changes": [
                    {"Action": "UPSERT", "ResourceRecordSet": record} for record in shadowed]})
            route53.change_resource_record_sets(
                HostedZoneId=domain_zone,
                ChangeBatch={"Changes": [
                    {"Action": "DELETE", "ResourceRecordSet": record} for record in shadowed]})
            carried = [f"{r.get('Name')}|{r.get('Type')}|{r.get('SetIdentifier') or ''}"
                       for r in shadowed]

    # Fingerprint: the delegated zone's id and the comment it was handed over with. The domain
    # and the namespace are the requester's words; a zone of its own for that namespace, and
    # what that zone says it is, are in the account only because this program ran, and
    # `ListHostedZones` — the call this fires on — returns both.
    return {"zone": zone_id, "created": created, "domain_zone": domain_zone,
            "name_servers": name_servers, "carried": carried,
            "fingerprint": [zone_id, HANDOVER_COMMENT],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
