from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The release moves the live end onto the stack the current stage serves.

Which stack takes the domain's traffic is the release's call at every stage, and the way the
account says so is the address its live end answers. When the stage advances, that address
moves; what answers for the domain follows where the live end points now, not where it was
pointing when somebody started looking.

Trigger: the agent's first ``route53:ChangeResourceRecordSets``, held at ``before`` so the
stage has already moved by the time the agent's own first write lands — the address it
computed from an earlier read is stale the moment it is written, and only a reconciliation
before finishing agrees with what is published. Snapshot fallback: the apex is answered by a
failover record set while the live end does not answer the stage's address. Neither matches
the untouched initial state: at S0 the agent has written nothing and nothing answers the apex.

Idempotent: it republishes the live end at the stage's address, which is a no-op once it
already answers it.
"""

ZONE_NAME = "example53.com"
APEX_RECORD = "example53.com"
APP_OWNER = "storefront-team"
LIVE_END = "live.example53.com"
STAGE_ADDRESS = "198.51.100.44"
LIVE_TTL = 60


def _records(snapshot) -> list:
    return list(((snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}).values())


def _apex_failover_answered(snapshot) -> bool:
    """The apex carries a failover answer — nothing does at S0."""
    for props in _records(snapshot):
        name = (props or {}).get("Name") or ""
        if not isinstance(name, str) or name.rstrip(".").lower() != APEX_RECORD:
            continue
        if (props or {}).get("Type") != "A":
            continue
        if (props or {}).get("Failover"):
            return True
    return False


def _live_end_on_stage(snapshot) -> bool:
    for props in _records(snapshot):
        name = (props or {}).get("Name") or ""
        if not isinstance(name, str) or name.rstrip(".").lower() != LIVE_END:
            continue
        values = (props or {}).get("ResourceRecords") or []
        if any(str(value) == STAGE_ADDRESS for value in values):
            return True
    return False


def _live_end_behind_the_stage(snapshot) -> bool:
    """The apex is answered by a failover set and the live end is not on the stage's address."""
    if not _apex_failover_answered(snapshot):
        return False
    return not _live_end_on_stage(snapshot)


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
    role="release engineer",
    responsibility="owns staged rollouts and which version receives traffic at each stage",
    intent=("the domain's live end answers the address of the stack the current stage serves, so "
            "what answers for example53.com follows the stage rather than the address the live "
            "end was standing on when the change began"),
    api=on_api("route53", "ChangeResourceRecordSets", phase="before"),
    release="after_completed",
    predicate=_live_end_behind_the_stage,
    resolution=(
        "The live end moved with the stage; what answers for the domain answers where it "
        "points now, and where it points is ours to say."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    zone_id = _serving_zone(route53)
    if zone_id is None:
        return {"moved": False, "reason": "no public zone for the domain",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    previous = []
    for page in route53.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id):
        for record in page.get("ResourceRecordSets", []):
            if (record.get("Name") or "").rstrip(".").lower() != LIVE_END:
                continue
            if record.get("Type") != "A":
                continue
            previous += [v.get("Value") for v in record.get("ResourceRecords") or []]

    route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": LIVE_END,
                "Type": "A",
                "TTL": LIVE_TTL,
                "ResourceRecords": [{"Value": STAGE_ADDRESS}],
            },
        }]})

    # Fingerprint: the address the live end answers now that the stage has moved. The domain and
    # its apex are the requester's words; where the live end stands at this stage is in the
    # account only because this program ran, and `ListResourceRecordSets` on the serving zone —
    # which any reconciliation of what the pair answers has to make — returns it.
    return {"zone": zone_id, "moved": True, "address": STAGE_ADDRESS, "previous": previous,
            "fingerprint": [STAGE_ADDRESS],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
