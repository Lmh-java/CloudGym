from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The cutover moves the application's active side onto the address it has reached.

Which side of the application is authoritative at this stage is the cutover's call, and the way
the account says where that side stands is the address its active endpoint's name answers. When
the stage advances, that address moves, and everything that stands for the active side follows
it: what is gated on that endpoint's health answers the endpoint being watched, not the address
it stood on when somebody started looking.

Trigger: the agent's first ``route53:ChangeResourceRecordSets``, held at ``after_success`` so
the stage has moved the moment the agent's own first write lands — an address it carried in is
stale as soon as it is written, and only a reconciliation before finishing agrees with what the
account publishes. Snapshot fallback: the application's name is answered while its active
endpoint does not answer the stage's address. Neither matches the untouched initial state: at
S0 the agent has written nothing, nothing answers the application's name and nothing answers
its active endpoint.

Idempotent: it republishes the active endpoint at the stage's address and re-states any active
answer that stands on another address, both no-ops once they answer it.
"""

APP_RECORD = "www.app.example53.com"
ACTIVE_ENDPOINT = "active.app.example53.com"
STAGE_ADDRESS = "198.51.100.11"
ENDPOINT_TTL = 60


def _records(snapshot) -> list:
    return list(((snapshot.get("resources") or {}).get("AWS::Route53::RecordSet") or {}).values())


def _app_answered(snapshot) -> bool:
    for props in _records(snapshot):
        name = (props or {}).get("Name") or ""
        if isinstance(name, str) and name.rstrip(".").lower() == APP_RECORD:
            return True
    return False


def _endpoint_behind_stage(snapshot) -> bool:
    """The application's name is answered while its active endpoint does not stand where the
    cutover has reached."""
    if not _app_answered(snapshot):
        return False
    for props in _records(snapshot):
        name = (props or {}).get("Name") or ""
        if not isinstance(name, str) or name.rstrip(".").lower() != ACTIVE_ENDPOINT:
            continue
        if STAGE_ADDRESS in ((props or {}).get("ResourceRecords") or []):
            return False
    return True


def _authoritative_zone(route53, name: str) -> str | None:
    """The public hosted zone the account has made authoritative for ``name``: the one whose
    own name is the longest suffix of it on a label boundary."""
    best = None
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page.get("HostedZones", []):
            if (zone.get("Config") or {}).get("PrivateZone"):
                continue
            zone_name = (zone.get("Name") or "").rstrip(".").lower()
            if not zone_name:
                continue
            if name == zone_name or name.endswith("." + zone_name):
                if best is None or len(zone_name) > len(best[0]):
                    best = (zone_name, zone["Id"].rsplit("/", 1)[-1])
    return best[1] if best else None


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("the application's active side stands where the cutover has reached: the active "
            "endpoint's name answers that address in the zone that answers for it, and whatever "
            "is gated on that endpoint's health answers the same address, so nothing answers "
            "the side the cutover has left"),
    api=on_api("route53", "ChangeResourceRecordSets", phase="after_success"),
    release="after_completed",
    predicate=_endpoint_behind_stage,
    resolution=(
        "What is gated answers where the account publishes that endpoint now, not where it "
        "stood when you looked."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    zone_id = _authoritative_zone(route53, ACTIVE_ENDPOINT)
    if zone_id is None:
        return {"moved": False, "reason": "no public zone answers for that endpoint",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    changes = [{
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": ACTIVE_ENDPOINT,
            "Type": "A",
            "TTL": ENDPOINT_TTL,
            "ResourceRecords": [{"Value": STAGE_ADDRESS}],
        },
    }]

    app_zone = _authoritative_zone(route53, APP_RECORD)
    behind = []
    if app_zone is not None:
        for page in route53.get_paginator("list_resource_record_sets").paginate(
                HostedZoneId=app_zone):
            for record in page.get("ResourceRecordSets", []):
                if (record.get("Name") or "").rstrip(".").lower() != APP_RECORD:
                    continue
                if record.get("Type") != "A" or record.get("Failover") != "PRIMARY":
                    continue
                answers = [r.get("Value") for r in record.get("ResourceRecords") or []]
                if answers == [STAGE_ADDRESS]:
                    continue
                moved = dict(record)
                moved["ResourceRecords"] = [{"Value": STAGE_ADDRESS}]
                behind.append(answers)
                if app_zone == zone_id:
                    changes.append({"Action": "UPSERT", "ResourceRecordSet": moved})
                else:
                    route53.change_resource_record_sets(
                        HostedZoneId=app_zone,
                        ChangeBatch={"Changes": [
                            {"Action": "UPSERT", "ResourceRecordSet": moved}]})

    route53.change_resource_record_sets(HostedZoneId=zone_id,
                                        ChangeBatch={"Changes": changes})

    # Fingerprint: the address the active endpoint answers now that the stage has moved. The
    # endpoint's name is the requester's word; where that side stands at this stage is in the
    # account only because this program ran, and `ListResourceRecordSets` on the zone that
    # answers for it — which any reconciliation of what the active side answers has to make —
    # returns it.
    return {"zone": zone_id, "moved": True, "address": STAGE_ADDRESS, "behind": behind,
            "fingerprint": [STAGE_ADDRESS],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
