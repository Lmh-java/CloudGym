from __future__ import annotations

import json
import os
import time

from harness.runtime import distract

"""The payments API publishes its own EC2 CPU reading, scoped to its own fleet.

The payments API runs on EC2 in this same account and shares its naming space. Its capacity
work needs the same reading anybody would ask for — average CPU across its instances, read in
two-minute periods, alarming upwards — so it publishes one, scoped by dimension to the
payments fleet, and hangs its own Route 53 watch off it. From that moment "a CloudWatch metric
alarm on that fleet's CPU" no longer picks out one thing in the account: an alarm with exactly
those settings is already there, and it answers for somebody else's instances.

Trigger: a snapshot showing an EC2 CPU reading in the account while the payments API's own is
not among them — the moment somebody starts reading that metric here, the payments API needs
its own reading to be the one that answers for its fleet. It never matches the untouched
initial state: at S0 nothing in the account reads EC2 CPU at all.

Idempotent: it republishes its alarm with the same settings, and it creates no second watch
when one is already bound to that alarm.
"""

SIBLING_ALARM = "payments-api-cpu-high"
SIBLING_FLEET = "payments-api-asg"
SIBLING_TICKET = "PAY-7781"
SIBLING_OWNER = "payments-team"
SIBLING_WORKLOAD = "payments-api"
SIBLING_DESCRIPTION = (
    "Payments API fleet CPU headroom; scoped to the payments fleet (capacity ticket PAY-7781)")
SIBLING_TAGS = [
    {"Key": "Owner", "Value": SIBLING_OWNER},
    {"Key": "Workload", "Value": SIBLING_WORKLOAD},
    {"Key": "Name", "Value": "payments-api-cpu"},
]


def _is_cpu_reading(props) -> bool:
    return ((props or {}).get("Namespace") == "AWS/EC2"
            and (props or {}).get("MetricName") == "CPUUtilization")


def _payments_reading_missing(snapshot) -> bool:
    """Somebody reads EC2 CPU in this account, and it is not the payments API."""
    alarms = (snapshot.get("resources") or {}).get("AWS::CloudWatch::Alarm") or {}
    if not isinstance(alarms, dict):
        return False
    readings = [p for p in alarms.values() if _is_cpu_reading(p)]
    if not readings:
        return False
    return not any((p or {}).get("AlarmName") == SIBLING_ALARM for p in alarms.values())


@distract(
    role="developer on a sibling application team",
    responsibility="owns a second application in the same account that shares the network and naming space",
    intent=("the payments API's own EC2 CPU reading is published for the payments fleet and "
            "scoped to it by dimension, and the one Route 53 watch bound to that reading is "
            "the payments API's own"),
    release="after_completed",
    predicate=_payments_reading_missing,
    resolution=(
        "That reading is ours and it is scoped to our own fleet; a watch that answers for "
        "yours hangs off a reading of yours, not ours."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    cloudwatch = boto3.client("cloudwatch", region_name=region)
    route53 = boto3.client("route53", region_name=region)

    cloudwatch.put_metric_alarm(
        AlarmName=SIBLING_ALARM,
        AlarmDescription=SIBLING_DESCRIPTION,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        EvaluationPeriods=2,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=120,
        Threshold=75,
        Dimensions=[{"Name": "AutoScalingGroupName", "Value": SIBLING_FLEET}],
        ActionsEnabled=False,
        Tags=SIBLING_TAGS,
    )

    bound = None
    for page in route53.get_paginator("list_health_checks").paginate():
        for check in page.get("HealthChecks", []):
            config = check.get("HealthCheckConfig") or {}
            if (config.get("AlarmIdentifier") or {}).get("Name") == SIBLING_ALARM:
                bound = check["Id"]
                break
        if bound:
            break

    created = False
    if bound is None:
        # A freshly published alarm is not always visible to Route 53 on the first try; the
        # watch is the point of this intent, so give the new reading a moment to settle.
        made = None
        for attempt in range(6):
            try:
                made = route53.create_health_check(
                    CallerReference=f"{SIBLING_WORKLOAD}-cpu-{time.time_ns()}",
                    HealthCheckConfig={
                        "Type": "CLOUDWATCH_METRIC",
                        "AlarmIdentifier": {"Name": SIBLING_ALARM, "Region": region},
                        "InsufficientDataHealthStatus": "Unhealthy",
                    },
                )
                break
            except Exception:  # noqa: BLE001 - retried below, raised on the last attempt
                if attempt == 5:
                    raise
                time.sleep(2)
        bound = made["HealthCheck"]["Id"]
        created = True
    route53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=bound, AddTags=SIBLING_TAGS)

    # Fingerprint: the name the payments API publishes its reading under and the fleet that
    # reading is scoped to. Both are in the account only because this program ran, and both
    # come back from `DescribeAlarms` (as `AlarmName` and as a `Dimensions` value); the name
    # also comes back from `ListHealthChecks`, as the alarm the payments watch is bound to.
    return {"alarm": SIBLING_ALARM, "fleet": SIBLING_FLEET, "ticket": SIBLING_TICKET,
            "check": bound, "check_created": created,
            "fingerprint": [SIBLING_ALARM, SIBLING_FLEET],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
