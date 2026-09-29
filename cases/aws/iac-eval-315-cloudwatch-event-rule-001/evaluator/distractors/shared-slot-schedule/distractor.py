from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The schedule this account runs for its daily 07:00 UTC slot.

The platform runs one rule per daily slot and lets the workloads scheduled for that hour
ride it, instead of every workload keeping a copy of the same schedule. "The schedule this
account runs for its daily slot" says nothing on its own about which rule that is; from the
moment the slot rule is published, it is that one, and a workload due at that hour is a
target on it.

Trigger: the agent's ``events:ListRules`` — the read that says which schedules this account
already runs — held at ``before`` so the slot rule is already among them when the list comes
back. Snapshot fallback: the agent has begun standing its own daily wiring up while no rule
is published for the slot. Neither matches the untouched initial state: at S0 the agent has
not looked yet and the account holds no EventBridge rule at all.

Idempotent: a no-op once the slot rule stands with the settings the platform publishes.
Targets are never written here — who rides the slot is each workload's own business — and no
other rule in the account is touched.
"""

SLOT_RULE = "platform-daily-0700"
SLOT_MARK = "shared daily slot"
SLOT_DESCRIPTION = "shared daily slot, 07:00 UTC, in service for this account's workloads"
SCHEDULE = "cron(0 7 * * ? *)"
FUNCTION = "cron-lambda-function"
EVENTS_PRINCIPAL = "events.amazonaws.com"
STAGED_MARK = "staged for the daily slot cutover"
SIBLING_MARK = "billing-digest daily digest"
ROLLBACK_MARK = "previous daily wiring kept restorable"
PROGRAM_MARKS = (SLOT_MARK, STAGED_MARK, SIBLING_MARK, ROLLBACK_MARK)


def _resources(snapshot, kind):
    resources = ((snapshot or {}).get("resources") or {}).get(kind) or {}
    return resources if isinstance(resources, dict) else {}


def _rules(snapshot):
    return {arn: props for arn, props in _resources(snapshot, "AWS::Events::Rule").items()
            if isinstance(props, dict)}


def _description(props) -> str:
    return str((props or {}).get("Description") or "")


def _mark_of(props) -> str:
    description = _description(props)
    return next((mark for mark in PROGRAM_MARKS if mark in description), "")


def _targets_function(props) -> bool:
    for target in (props or {}).get("Targets") or []:
        arn = target.get("Arn") if isinstance(target, dict) else None
        if isinstance(arn, str) and ":function:" in arn:
            if arn.split(":function:", 1)[1].split(":")[0] == FUNCTION:
                return True
    return False


def _agent_started(snapshot) -> bool:
    """The agent has begun wiring the function's daily run up.

    Either some rule that is not the kept previous generation fires the function — including
    the slot rule, whose targets no program of this case writes — or an invoke grant stands on
    the function that does not belong to that kept generation.
    """
    rules = _rules(snapshot)
    for props in rules.values():
        if _targets_function(props) and _mark_of(props) != ROLLBACK_MARK:
            return True
    kept = {arn for arn, props in rules.items() if _mark_of(props) == ROLLBACK_MARK}
    for props in _resources(snapshot, "AWS::Lambda::Permission").values():
        if not isinstance(props, dict):
            continue
        if str(props.get("Principal") or "") != EVENTS_PRINCIPAL:
            continue
        if str(props.get("SourceArn") or "") not in kept:
            return True
    return False


def _slot_unpublished(snapshot) -> bool:
    """The function's daily wiring is going up and no rule is published for the slot."""
    if not _agent_started(snapshot):
        return False
    return not any(SLOT_MARK in _description(props) for props in _rules(snapshot).values())


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the account runs one schedule for its daily 07:00 UTC slot — the rule "
            "platform-daily-0700, enabled, firing daily at that hour and described as the "
            "shared slot in service — and the workloads due at that hour ride it rather than "
            "each keeping a copy of the same schedule"),
    api=on_api("events", "ListRules", phase="before"),
    release="after_completed",
    predicate=_slot_unpublished,
    resolution=("A schedule for that hour is already running here; a workload rides the one "
                "in service instead of standing up another."),
)
def run() -> dict:
    import boto3

    events = boto3.client("events", region_name=os.environ.get("AWS_REGION") or "us-east-1")

    held = None
    for page in events.get_paginator("list_rules").paginate():
        for rule in page.get("Rules", []):
            if rule.get("Name") == SLOT_RULE:
                held = rule
    published = False
    if (held or {}).get("ScheduleExpression") != SCHEDULE \
            or (held or {}).get("State") != "ENABLED" \
            or SLOT_MARK not in str((held or {}).get("Description") or ""):
        events.put_rule(Name=SLOT_RULE, ScheduleExpression=SCHEDULE, State="ENABLED",
                        Description=SLOT_DESCRIPTION)
        published = True

    # Fingerprint: the slot rule the platform publishes — its name and the words it is
    # described by, both of which come back with the very ListRules this fires on and with
    # any later read of the schedules this account runs.
    return {"slot_rule": SLOT_RULE, "published": published, "schedule": SCHEDULE,
            "fingerprint": [{"say": [SLOT_RULE, SLOT_MARK], "seen": SLOT_RULE}],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
