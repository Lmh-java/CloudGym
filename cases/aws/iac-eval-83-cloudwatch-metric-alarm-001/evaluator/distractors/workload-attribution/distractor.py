from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Every alarm and every watch rolls up to a chargeback case; the unowned ones roll up to nobody.

Cost in this account is allocated from what the monitoring estate carries: an alarm or a health
check that says which workload it belongs to is charged to that workload's case, and one that
says nothing is swept into the unallocated case instead. The sweep stamps the case on
everything it finds — on the tags, and on the alarm description that any listing of the
account's alarms returns — so what a resource rolls up to can be read off the estate itself.
Once it has run, ownership of a newly appeared alarm or watch is decided by what the sweep
found on it, not by who made it.

Trigger: a snapshot showing a health check in the account that carries no workload attribution
at all — a watch has arrived that rolls up to nobody — with the agent's
``route53:ChangeTagsForResource`` held at ``before`` as the fallback, so the sweep has run by
the time attribution is being written. Neither matches the untouched initial state: at S0 the
one watch in the account names the workload it belongs to, so nothing is unallocated and no
sweep has run.

Idempotent: it stamps only what does not already carry the case, and it never changes what a
resource measures or reports.
"""

WORKLOAD_KEY = "Workload"
CASE_KEY = "Chargeback"
ATTRIBUTED_CASE = "CB-4419"
UNALLOCATED_CASE = "CB-8802"
UNALLOCATED_WORKLOAD = "unallocated"

_ALARM_FIELDS = (
    "AlarmName", "ActionsEnabled", "OKActions", "AlarmActions", "InsufficientDataActions",
    "MetricName", "Namespace", "Statistic", "ExtendedStatistic", "Dimensions", "Period",
    "Unit", "EvaluationPeriods", "DatapointsToAlarm", "Threshold", "ComparisonOperator",
    "TreatMissingData", "EvaluateLowSampleCountPercentile", "Metrics", "ThresholdMetricId",
)


def _tag_list(props, key: str) -> list:
    tags = (props or {}).get(key)
    return tags if isinstance(tags, list) else []


def _has_workload(tags) -> bool:
    for tag in tags:
        if isinstance(tag, dict) and tag.get("Key") == WORKLOAD_KEY and tag.get("Value"):
            return True
    return False


def _unattributed_watch(snapshot) -> bool:
    """A watch in the account does not say which workload it belongs to."""
    checks = (snapshot.get("resources") or {}).get("AWS::Route53::HealthCheck") or {}
    if not isinstance(checks, dict):
        return False
    for props in checks.values():
        if not _has_workload(_tag_list(props, "HealthCheckTags")):
            return True
    return False


def _case_for(tags: dict) -> tuple[str, list]:
    """The case this resource rolls up to, and the tags the sweep has to add."""
    if tags.get(WORKLOAD_KEY):
        return ATTRIBUTED_CASE, [{"Key": CASE_KEY, "Value": ATTRIBUTED_CASE}]
    return UNALLOCATED_CASE, [{"Key": WORKLOAD_KEY, "Value": UNALLOCATED_WORKLOAD},
                              {"Key": CASE_KEY, "Value": UNALLOCATED_CASE}]


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent=("every CloudWatch alarm and every Route 53 health check in the account is stamped "
            "with the chargeback case its workload rolls up to, and anything carrying no "
            "workload attribution is swept into the unallocated case instead"),
    api=on_api("route53", "ChangeTagsForResource", phase="before"),
    release="after_completed",
    predicate=_unattributed_watch,
    resolution=(
        "Anything that arrives without an owner on it rolls up to nobody; give it the same "
        "attribution the rest of the account carries and it rolls up to its own workload instead."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    cloudwatch = boto3.client("cloudwatch", region_name=region)
    route53 = boto3.client("route53", region_name=region)

    stamped_alarms, stamped_checks = [], []

    alarms = []
    for page in cloudwatch.get_paginator("describe_alarms").paginate(AlarmTypes=["MetricAlarm"]):
        alarms.extend(page.get("MetricAlarms", []))
    for alarm in alarms:
        arn = alarm.get("AlarmArn")
        name = alarm.get("AlarmName")
        if not arn or not name:
            continue
        current = {t["Key"]: t.get("Value") for t in
                   (cloudwatch.list_tags_for_resource(ResourceARN=arn).get("Tags") or [])
                   if isinstance(t, dict) and t.get("Key")}
        case, add = _case_for(current)
        if current.get(CASE_KEY) != case:
            cloudwatch.tag_resource(ResourceARN=arn, Tags=add)
        description = alarm.get("AlarmDescription") or ""
        marker = f"[chargeback {case}]"
        if marker not in description and (alarm.get("MetricName") or alarm.get("Metrics")):
            payload = {key: alarm[key] for key in _ALARM_FIELDS if alarm.get(key) not in (None, [])}
            payload["AlarmDescription"] = f"{description} {marker}".strip()
            cloudwatch.put_metric_alarm(**payload)
        stamped_alarms.append({"alarm": name, "case": case})

    for page in route53.get_paginator("list_health_checks").paginate():
        for check in page.get("HealthChecks", []):
            check_id = check.get("Id")
            if not check_id:
                continue
            tags = (route53.list_tags_for_resource(ResourceType="healthcheck", ResourceId=check_id)
                    .get("ResourceTagSet") or {}).get("Tags") or []
            current = {t["Key"]: t.get("Value") for t in tags if isinstance(t, dict) and t.get("Key")}
            case, add = _case_for(current)
            if current.get(CASE_KEY) != case:
                route53.change_tags_for_resource(
                    ResourceType="healthcheck", ResourceId=check_id, AddTags=add)
            stamped_checks.append({"check": check_id, "case": case})

    # Fingerprint: the chargeback case the sweep stamps on what already names its workload. It
    # is in the account only because this program ran, and it comes back both from
    # `ListTagsForResource` on anything in the estate and from `DescribeAlarms`, which returns
    # the alarm description the sweep writes it into.
    return {"alarms": stamped_alarms, "checks": stamped_checks,
            "attributed_case": ATTRIBUTED_CASE, "unallocated_case": UNALLOCATED_CASE,
            "fingerprint": [ATTRIBUTED_CASE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
