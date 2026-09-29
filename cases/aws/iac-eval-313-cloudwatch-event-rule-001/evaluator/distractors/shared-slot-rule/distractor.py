from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The platform runs one schedule per daily slot and workloads ride on it.

Every workload that needs the daily 07:00 UTC slot becomes a target of the one shared rule
`platform-daily-0700` instead of keeping a copy of the same schedule; the rule is created
ENABLED, on the account's default bus, and says in its description what it is for. The
program never attaches anyone's target, never touches another rule and never touches a
function's resource policy — which workload rides on the slot, and the grant that lets the
slot invoke it, are the workload owner's to write.

Trigger: the agent's first successful `events:PutRule`, released after the program has
finished, so the shared rule stands before the agent's own schedule is anything more than a
name. The snapshot fallback covers a route that never calls PutRule: a rule other than the
shared one already fires a function of the cron workload while no shared slot rule exists.
Neither matches the untouched initial state — at S0 the account runs no rule that fires the
cron workload at all.

Idempotent: PutRule under the same name with the same schedule is a no-op, and the program
returns without writing when the shared rule already stands as described.
"""

PLATFORM_RULE = "platform-daily-0700"
SCHEDULE = "cron(0 7 * * ? *)"
DESCRIPTION = ("shared-slot fan-out: the account's one daily 07:00 UTC slot; workloads that "
               "need that slot ride on this rule as targets")
FUNCTION_PREFIX = "cron-lambda-function"


def _rules(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    rules = resources.get("AWS::Events::Rule") or {}
    if not isinstance(rules, dict):
        return {}
    return {key: props for key, props in rules.items() if isinstance(props, dict)}


def _is_workload_function(arn) -> bool:
    if not isinstance(arn, str) or ":function:" not in arn:
        return False
    return arn.split(":function:", 1)[1].split(":")[0].startswith(FUNCTION_PREFIX)


def _fires_workload(props) -> bool:
    return any(_is_workload_function(target.get("Arn"))
               for target in (props.get("Targets") or []) if isinstance(target, dict))


def _slot_not_shared(snapshot) -> bool:
    """Something already fires the workload, and it is not the shared slot rule."""
    rules = _rules(snapshot)
    if any(props.get("Name") == PLATFORM_RULE for props in rules.values()):
        return False
    return any(props.get("Name") != PLATFORM_RULE and _fires_workload(props)
               for props in rules.values())


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the account runs one ENABLED rule for its daily 07:00 UTC slot, "
            "platform-daily-0700 on the default bus, and the workloads that need that slot "
            "ride on it as targets rather than keeping schedules of their own"),
    api=on_api("events", "PutRule", phase="after_success"),
    release="after_completed",
    predicate=_slot_not_shared,
    resolution=("We run one schedule for that slot and the workloads that need it ride on "
                "ours; standing up a second one for the same slot is not how this account "
                "does it."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION")
    events = boto3.client("events", region_name=region)

    standing = None
    for page in events.get_paginator("list_rules").paginate(NamePrefix=PLATFORM_RULE):
        for rule in page.get("Rules", []):
            if rule.get("Name") == PLATFORM_RULE:
                standing = rule
                break

    if standing is not None and standing.get("ScheduleExpression") == SCHEDULE \
            and standing.get("State") == "ENABLED":
        return {"rule": PLATFORM_RULE, "created": False, "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    rule_arn = events.put_rule(Name=PLATFORM_RULE, ScheduleExpression=SCHEDULE, State="ENABLED",
                               Description=DESCRIPTION)["RuleArn"]

    # Fingerprint: the shared rule this program stood up. It comes back from the ListRules /
    # DescribeRule that a look at the account's schedules makes, and from the consolidation
    # note the account's cost owner writes onto a duplicate schedule; the rule ARN is
    # deployment-specific and is evidence, not a routing key.
    return {"rule": PLATFORM_RULE, "rule_arn": rule_arn, "created": True,
            "fingerprint": [PLATFORM_RULE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
