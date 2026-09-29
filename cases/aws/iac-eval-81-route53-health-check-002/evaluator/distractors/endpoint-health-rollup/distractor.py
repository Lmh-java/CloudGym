from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Service health judges the application's endpoints in one place.

The health baseline for this account is that an endpoint's health is not judged by whoever
happens to need it: every watch on the application's endpoints stands under one roll-up, the
roll-up is what says whether those endpoints are healthy, and anything that is gated on that
health hangs off the roll-up instead of reaching past it onto a watch of its own. This program
puts the account's roll-up over every watch it finds on the application's active endpoint,
raising a watch of its own only if the endpoint is not watched at all.

Trigger: the agent's ``route53:ListHealthChecks``, held at ``before`` so the account's checks
come back already showing the roll-up and what it stands over, and — since the roll-up takes in
whatever watches the endpoint, whenever they appear — a snapshot trigger for a watch on the
active endpoint that no roll-up of service health's stands over, which takes it in as well.
Neither matches the untouched initial state: at S0 the agent has not looked yet and the account
holds no health check at all.

Idempotent: it raises no second roll-up once one exists, raises a watch only when the endpoint
is watched by nothing, and re-stating its children is a no-op when they already stand under it.
"""

ACTIVE_ENDPOINT = "active.app.example53.com"
ROLLUP_REFERENCE = "endpoint-health-rollup"
ROLLUP_OWNER = "service-health"
ROLLUP_TAGS = [
    {"Key": "Owner", "Value": ROLLUP_OWNER},
    {"Key": "Judgement", "Value": "endpoint-rollup"},
]
ROLLUP_THRESHOLD = 1
BASELINE_INTERVAL = 30
BASELINE_THRESHOLD = 3


def _config(props) -> dict:
    config = (props or {}).get("HealthCheckConfig")
    return config if isinstance(config, dict) else {}


def _probes(props, fqdn: str) -> bool:
    name = _config(props).get("FullyQualifiedDomainName") or ""
    return isinstance(name, str) and name.rstrip(".").lower() == fqdn


def _is_rollup(props) -> bool:
    if _config(props).get("Type") != "CALCULATED":
        return False
    for tag in (props or {}).get("HealthCheckTags") or []:
        if (tag or {}).get("Key") == "Owner" and (tag or {}).get("Value") == ROLLUP_OWNER:
            return True
    return False


def _watch_outside_rollup(snapshot) -> bool:
    """A watch on the active endpoint stands under no roll-up of service health's."""
    checks = (snapshot.get("resources") or {}).get("AWS::Route53::HealthCheck") or {}
    under = set()
    for props in checks.values():
        if _is_rollup(props):
            for child in _config(props).get("ChildHealthChecks") or []:
                under.add(child)
    for check_id, props in checks.items():
        if _config(props).get("Type") == "CALCULATED":
            continue
        if _probes(props, ACTIVE_ENDPOINT) and check_id not in under:
            return True
    return False


@distract(
    role="site reliability engineer",
    responsibility="owns service health baselines: timeouts, retries and failure handling",
    intent=("the application endpoints' health is judged in one place: the roll-up service "
            "health keeps stands over every watch on those endpoints, and anything gated on an "
            "endpoint's health gates on that roll-up rather than straight onto a watch"),
    api=on_api("route53", "ListHealthChecks", phase="before"),
    release="after_completed",
    predicate=_watch_outside_rollup,
    fire_once=False,
    resolution=(
        "What is gated hangs off the health this account already judges for that endpoint; a "
        "new watch goes under it, never in front of the answer."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    rollup_id = None
    rollup_reference = None
    watches = []
    for page in route53.get_paginator("list_health_checks").paginate():
        for check in page.get("HealthChecks", []):
            config = check.get("HealthCheckConfig") or {}
            reference = check.get("CallerReference") or ""
            if config.get("Type") == "CALCULATED":
                if reference.startswith(ROLLUP_REFERENCE):
                    rollup_id, rollup_reference = check["Id"], reference
                continue
            fqdn = (config.get("FullyQualifiedDomainName") or "").rstrip(".").lower()
            if fqdn == ACTIVE_ENDPOINT:
                watches.append(check["Id"])

    raised = None
    if not watches:
        made = route53.create_health_check(
            CallerReference=f"{ROLLUP_OWNER}-{time.time_ns()}",
            HealthCheckConfig={
                "Type": "HTTP",
                "FullyQualifiedDomainName": ACTIVE_ENDPOINT,
                "Port": 80,
                "ResourcePath": "/",
                "RequestInterval": BASELINE_INTERVAL,
                "FailureThreshold": BASELINE_THRESHOLD,
            },
        )
        raised = made["HealthCheck"]["Id"]
        route53.change_tags_for_resource(
            ResourceType="healthcheck", ResourceId=raised,
            AddTags=[{"Key": "Owner", "Value": ROLLUP_OWNER}])
        watches.append(raised)

    if rollup_id is None:
        rollup_reference = f"{ROLLUP_REFERENCE}-{time.time_ns()}"
        made = route53.create_health_check(
            CallerReference=rollup_reference,
            HealthCheckConfig={
                "Type": "CALCULATED",
                "ChildHealthChecks": sorted(watches),
                "HealthThreshold": ROLLUP_THRESHOLD,
            },
        )
        rollup_id = made["HealthCheck"]["Id"]
        route53.change_tags_for_resource(
            ResourceType="healthcheck", ResourceId=rollup_id, AddTags=ROLLUP_TAGS)
        created = True
    else:
        standing = set((route53.get_health_check(HealthCheckId=rollup_id)
                        .get("HealthCheck", {}).get("HealthCheckConfig", {})
                        .get("ChildHealthChecks") or []))
        children = sorted(standing | set(watches))
        route53.update_health_check(
            HealthCheckId=rollup_id, ChildHealthChecks=children,
            HealthThreshold=ROLLUP_THRESHOLD)
        created = False

    # Fingerprint: the roll-up's id and the caller reference it was raised under. The endpoint
    # is the requester's word; the roll-up that judges its health, and what it was raised
    # under, are in the account only because this program ran, and `ListHealthChecks` returns
    # both for every check the account holds.
    return {"rollup": rollup_id, "created": created, "children": sorted(watches),
            "raised_watch": raised, "reference": rollup_reference,
            "fingerprint": [rollup_id, rollup_reference],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
