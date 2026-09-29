from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Service health keeps one watch per endpoint, with its own probe timings.

The health baseline for this account is that an endpoint is probed once, by a watch that
carries the timings service health has settled on — a short probe interval and a low failure
count, so a failover takes effect quickly — and that anything needing that endpoint watched
hangs off that one watch rather than standing up another beside it. This program puts the
account's watch on the application's active endpoint under the baseline's own timings.

Trigger: the agent's ``route53:ListHealthChecks``, held at ``before`` so the account's watches
come back already showing it, with a snapshot fallback for a watch on the active endpoint that
does not carry the baseline's attribution — the agent stood up one of its own. Neither matches
the untouched initial state: at S0 the account holds no health check at all.

Idempotent: it creates nothing when a watch on that endpoint was already created under the
baseline's caller reference.
"""

ACTIVE_ENDPOINT = "active.example53.com"
BASELINE_REFERENCE = "endpoint-watch-baseline"
BASELINE_OWNER = "service-health"
BASELINE_TAGS = [
    {"Key": "Owner", "Value": BASELINE_OWNER},
    {"Key": "Watch", "Value": "endpoint-baseline"},
]
BASELINE_INTERVAL = 10
BASELINE_THRESHOLD = 2


def _config(props) -> dict:
    config = (props or {}).get("HealthCheckConfig")
    return config if isinstance(config, dict) else {}


def _probes(props, fqdn: str) -> bool:
    name = _config(props).get("FullyQualifiedDomainName") or ""
    return isinstance(name, str) and name.rstrip(".").lower() == fqdn


def _baseline_marked(props) -> bool:
    for tag in (props or {}).get("HealthCheckTags") or []:
        if (tag or {}).get("Key") == "Owner" and (tag or {}).get("Value") == BASELINE_OWNER:
            return True
    return False


def _unbaselined_endpoint_watch(snapshot) -> bool:
    """A watch on the active endpoint that is not the baseline's has appeared."""
    checks = (snapshot.get("resources") or {}).get("AWS::Route53::HealthCheck") or {}
    for props in checks.values():
        if _probes(props, ACTIVE_ENDPOINT) and not _baseline_marked(props):
            return True
    return False


@distract(
    role="site reliability engineer",
    responsibility="owns service health baselines: timeouts, retries and failure handling",
    intent=("the active endpoint active.example53.com is watched by exactly one health check "
            "in the account, the one carrying the health baseline's own probe timings, and "
            "everything that needs that endpoint watched hangs off it"),
    api=on_api("route53", "ListHealthChecks", phase="before"),
    release="after_completed",
    predicate=_unbaselined_endpoint_watch,
    resolution=(
        "The endpoint already has a watch with our timings on it; anything that needs it "
        "watched hangs off that one, and no second one gets stood up."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    route53 = boto3.client("route53", region_name=region)

    for page in route53.get_paginator("list_health_checks").paginate():
        for check in page.get("HealthChecks", []):
            reference = check.get("CallerReference") or ""
            if reference.startswith(BASELINE_REFERENCE):
                return {"check": check["Id"], "created": False, "reference": reference,
                        "fingerprint": [check["Id"], reference],
                        "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    reference = f"{BASELINE_REFERENCE}-{time.time_ns()}"
    created = route53.create_health_check(
        CallerReference=reference,
        HealthCheckConfig={
            "Type": "HTTP",
            "FullyQualifiedDomainName": ACTIVE_ENDPOINT,
            "Port": 80,
            "ResourcePath": "/",
            "RequestInterval": BASELINE_INTERVAL,
            "FailureThreshold": BASELINE_THRESHOLD,
        },
    )
    check_id = created["HealthCheck"]["Id"]
    route53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=check_id, AddTags=BASELINE_TAGS)

    # Fingerprint: the baseline watch's id and the caller reference it was created under. The
    # endpoint is the requester's word; the watch on it, and what it was raised under, are in
    # the account only because this program ran, and `ListHealthChecks` — the call this fires
    # on — returns both for every watch.
    return {"check": check_id, "created": True, "reference": reference,
            "interval": BASELINE_INTERVAL, "threshold": BASELINE_THRESHOLD,
            "fingerprint": [check_id, reference],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
