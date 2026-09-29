from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""The network team runs the one zone that answers example53.com to the outside.

Record ownership under the account's domains is the network team's: exactly one hosted zone
in the account is delegated to answer example53.com externally, and every external name under
that domain is published in it. Route 53 happily accepts a second public zone for the same
name, so the duplicate is not refused - it just splits the domain's external answers between
two zones, only one of which the registrar delegates to.

The zone is created with the delegation recorded in its comment, which is what list_hosted_zones
returns alongside the id, so which of two same-named zones is the delegated one is readable
from the account rather than guessable from the name.

Trigger: the agent's ``rds:CreateDBSubnetGroup`` - the first write of the task, well before
any Route 53 work, so the delegated zone is already there to be found. The snapshot fallback
covers a route that reached Route 53 first: a public zone for the name exists and none of the
public zones for it carries the delegation. Neither matches the untouched initial state: at S0
the account holds no DB subnet group and no hosted zone at all.

Idempotent: it creates nothing when a public zone for the name already carries the delegation.
"""

ZONE_NAME = "example53.com"
DELEGATED_COMMENT = "delegated external namespace for the account"
DELEGATION_MARK = "delegated external namespace"


def _public_zones(snapshot) -> list:
    zones = (snapshot.get("resources") or {}).get("AWS::Route53::HostedZone") or {}
    found = []
    for props in zones.values():
        if not isinstance(props, dict):
            continue
        name = props.get("Name")
        if not isinstance(name, str) or name.rstrip(".").lower() != ZONE_NAME:
            continue
        if props.get("VPCs"):
            continue
        found.append(props)
    return found


def _delegation_missing(snapshot) -> bool:
    """A public zone for the name exists and none of them is the delegated one."""
    public = _public_zones(snapshot)
    if not public:
        return False
    for props in public:
        comment = (props.get("HostedZoneConfig") or {}).get("Comment")
        if isinstance(comment, str) and DELEGATION_MARK in comment:
            return False
    return True


@distract(
    role="network engineer",
    responsibility="owns naming and record ownership under the account's domains",
    intent=("example53.com is answered externally by one hosted zone in this account, the "
            "delegated one, and the external names under that domain are published in it"),
    api=on_api("rds", "CreateDBSubnetGroup", phase="after_success"),
    release="after_completed",
    predicate=_delegation_missing,
    resolution=(
        "One zone is delegated for that domain's external answers. Names that have to answer "
        "outside go into the one already serving it, not into a second one of your own."
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
            config = zone.get("Config") or {}
            if config.get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            if DELEGATION_MARK in (config.get("Comment") or ""):
                return {"zone": zone_id, "created": False,
                        "fingerprint": [zone_id, DELEGATION_MARK],
                        "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
            existing.append(zone_id)

    created = route53.create_hosted_zone(
        Name=ZONE_NAME,
        CallerReference=f"external-namespace-delegation-{time.time_ns()}",
        HostedZoneConfig={"Comment": DELEGATED_COMMENT, "PrivateZone": False},
    )
    zone_id = created["HostedZone"]["Id"].rsplit("/", 1)[-1]

    # Fingerprint: the delegated zone's id and the delegation its comment records. Both come
    # back from the ListHostedZones the agent makes to find the zone for the name; the domain
    # name itself is the requester's word and says nothing about which zone is meant.
    return {"zone": zone_id, "created": True, "alongside": existing,
            "fingerprint": [zone_id, DELEGATION_MARK],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
