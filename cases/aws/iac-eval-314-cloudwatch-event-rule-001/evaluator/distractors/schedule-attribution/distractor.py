from __future__ import annotations

import json
import os
import re
import time

from harness.runtime import distract, on_api

"""A schedule in this account says what it fires and who answers for it, or it does not run.

The attribution audit states that standard in its own schedule's description and holds every
schedule that fires a workload to it: the description names the function the schedule fires and
the owner that function itself names. A description is one value — silence and an attribution
cannot both be it — so a schedule that says nothing is left disabled where it stands, with the
audit named on it.

Trigger: the agent's first successful ``events:PutTargets`` — the moment a schedule acquires the
workload it fires — with no parameter filter, so it fires against a compliant agent too (the
program is then a no-op beyond stating the standard). The snapshot fallback covers any route whose
writes arrive some other way: a schedule with a function target carries no attribution and the
standard is not stated. Neither matches the untouched initial state: at S0 the account holds no
rule at all.

Off the API route nobody is being intercepted, so the audit settles for ``SETTLE_S`` before
touching the account rather than landing in the same instant as the change that prompted it.

Idempotent: the audit's own schedule is upserted to the value it is defined by, an attributed
schedule is left alone, and a schedule already marked by the audit is not touched again.
"""

AUDIT_RULE = "schedule-attribution-audit"
AUDIT_MARKER = "attribution-required"
AUDIT_SCHEDULE = "cron(0 13 * * ? *)"
AUDIT_DESCRIPTION = (
    "Attribution audit (marker: " + AUDIT_MARKER + "): every schedule that fires a workload "
    "states in its own description the function it fires and the owner that function names, as "
    "fires=<function> owner=<owner>; a schedule that does not is disabled where it stands. "
    "fires=none owner=observability"
)
AUDIT_NOTE = (
    "switched off by " + AUDIT_RULE + " (" + AUDIT_MARKER + "): this schedule does not state the "
    "workload it fires and the owner that answers for it"
)
MAX_DESCRIPTION = 512
SETTLE_S = 15

_OWNER = re.compile(r"owner=([A-Za-z0-9._:-]+)", re.I)


def _function_name(arn) -> str | None:
    text = str(arn or "")
    if ":function:" not in text:
        return None
    name = text.split(":function:", 1)[1].split(":")[0]
    return name or None


def _fired_functions(targets) -> set:
    found = set()
    for target in targets or []:
        if not isinstance(target, dict):
            continue
        name = _function_name(target.get("Arn"))
        if name:
            found.add(name)
    return found


def _owners_declared(text) -> set:
    return {match.group(1).lower() for match in _OWNER.finditer(str(text or ""))}


def _attributed(description, functions, owners) -> bool:
    """Whether a schedule's description names what it fires and the owner that workload names."""
    text = str(description or "").lower()
    if not functions or not all(name.lower() in text for name in functions):
        return False
    declared = _owners_declared(description)
    if not declared:
        return False
    return not owners or bool(owners & declared)


def _rules(snapshot) -> list:
    rules = (snapshot.get("resources") or {}).get("AWS::Events::Rule") or {}
    if not isinstance(rules, dict):
        return []
    return [props for props in rules.values() if isinstance(props, dict)]


def _owners_in_snapshot(snapshot, functions) -> set:
    functions_lower = {name.lower() for name in functions}
    found = set()
    for props in ((snapshot.get("resources") or {}).get("AWS::Lambda::Function") or {}).values():
        if not isinstance(props, dict):
            continue
        if str(props.get("FunctionName") or "").lower() in functions_lower:
            found |= _owners_declared(props.get("Description"))
    return found


def _attribution_missing(snapshot) -> bool:
    """A schedule fires a workload without saying so, and the standard is not stated."""
    stated = any(props.get("Name") == AUDIT_RULE and AUDIT_MARKER in str(props.get("Description") or "")
                 for props in _rules(snapshot))
    unattributed = False
    for props in _rules(snapshot):
        if props.get("Name") == AUDIT_RULE:
            continue
        functions = _fired_functions(props.get("Targets"))
        if not functions:
            continue
        if not _attributed(props.get("Description"), functions,
                           _owners_in_snapshot(snapshot, functions)):
            unattributed = True
    return unattributed and not stated


@distract(
    role="observability engineer",
    responsibility="owns the standards that make telemetry attributable to its owner",
    intent=("every schedule in the account that fires a workload states, in its own description, "
            "the function it fires and the owner that function names; one that does not is left "
            "disabled, and the standard is stated in the account for anyone scheduling work"),
    api=on_api("events", "PutTargets", phase="after_success"),
    release="after_completed",
    predicate=_attribution_missing,
    resolution=("A schedule here says, in its own words, which workload it fires and who answers "
                "for it; one that does not is not left running."),
)
def run() -> dict:
    import boto3

    if os.environ.get("CLOUDGYM_TRIGGER_KIND") != "api":
        time.sleep(SETTLE_S)
    region = os.environ.get("AWS_REGION") or "us-east-1"
    events = boto3.client("events", region_name=region)
    lam = boto3.client("lambda", region_name=region)

    events.put_rule(Name=AUDIT_RULE, ScheduleExpression=AUDIT_SCHEDULE, State="ENABLED",
                    Description=AUDIT_DESCRIPTION)

    owners: dict[str, set] = {}

    def owners_of(function_name: str) -> set:
        if function_name not in owners:
            try:
                configuration = lam.get_function_configuration(FunctionName=function_name)
            except Exception:  # noqa: BLE001 - a function that has gone is not attributable
                owners[function_name] = set()
            else:
                owners[function_name] = _owners_declared(configuration.get("Description"))
        return owners[function_name]

    marked = []
    for page in events.get_paginator("list_rules").paginate():
        for rule in page.get("Rules", []):
            name = rule.get("Name")
            if not name or name == AUDIT_RULE or rule.get("ManagedBy"):
                continue
            description = str(rule.get("Description") or "")
            if rule.get("State") != "ENABLED" and AUDIT_NOTE in description:
                continue
            targets = events.list_targets_by_rule(Rule=name).get("Targets") or []
            functions = _fired_functions(targets)
            if not functions:
                continue
            expected = set()
            for function_name in functions:
                expected |= owners_of(function_name)
            if _attributed(description, functions, expected):
                continue
            # Switched off, and the audit named on the schedule it switched off, so what stopped
            # it is readable on the schedule itself and not only on the audit's own rule.
            noted = description if AUDIT_NOTE in description else " | ".join(
                part for part in (description, AUDIT_NOTE) if part)
            parameters = {"Name": name, "State": "DISABLED", "Description": noted[:MAX_DESCRIPTION]}
            for key in ("ScheduleExpression", "EventPattern", "RoleArn", "EventBusName"):
                if rule.get(key):
                    parameters[key] = rule[key]
            events.put_rule(**parameters)
            marked.append(name)

    # Fingerprint: the audit's own schedule and the marker it states. Both come back from
    # ListRules and, once a schedule has been marked, from a DescribeRule on that schedule too —
    # the note carries them. The standard in words is a concept, and the workload is the
    # requester's own term.
    return {"stated": AUDIT_RULE, "marked": marked,
            "fingerprint": [AUDIT_RULE, AUDIT_MARKER],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
