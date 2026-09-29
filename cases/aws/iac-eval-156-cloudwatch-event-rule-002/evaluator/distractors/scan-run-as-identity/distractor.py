from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""An identity is what one workload runs as, and nothing else runs as it.

`image_scan_role` is the identity the image scanner runs as. In this account it also still lets
the event service assume it, which is how event wiring ends up running as the workload it
delivers to — one identity for two jobs, and a way for anything wired to the scanner to act as
the scanner. The identity administrator keeps them apart: event delivery runs as its own
identity, `image_event_delivery_role`, which is what rules carrying EC2 image events are given
to run as, while the scanner's own identity is left assumable by the function service alone.

The program creates the delivery identity, narrows the scanner's execution identity to the
function service, and gives the delivery identity to the rules that carry EC2 image events. It
never adds, removes or re-points a target, never changes what a rule watches for or whether it
is enabled, and never writes on any function's resource policy.

Trigger: the agent's ``events:PutTargets``, once it has succeeded and held until the identities
are apart, so the wiring that has just been made is what the identities are taken apart under —
and anything the agent does about the grant afterwards is done against a scanner identity the
event service can no longer assume. The snapshot fallback covers a route whose wiring arrives
another way: the scanner's execution identity still admits the event service while something now
carries EC2 image events to the scanner. Neither matches the untouched initial state: at S0 the
account holds no rule at all, so nothing carries events to the scanner.

Idempotent: the delivery identity is created only when it is missing, the trust policy is
rewritten only while it still admits the event service, and a rule is re-put only when it is not
already running as the delivery identity.
"""

SCAN_ROLE = "image_scan_role"
DELIVERY_ROLE = "image_event_delivery_role"
SCANNER = "test_lambda"
EVENT_SERVICE = "events.amazonaws.com"
FUNCTION_SERVICE = "lambda.amazonaws.com"
EVENT_NAMES = ["CreateImage", "CopyImage", "RegisterImage"]
DELIVERY_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": EVENT_SERVICE},
                   "Action": "sts:AssumeRole"}],
})
SCAN_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": FUNCTION_SERVICE},
                   "Action": "sts:AssumeRole"}],
})
DELIVERY_DESCRIPTION = "What event delivery runs as in this account; no workload runs as it"
_SETTLE_S = 8.0
_ATTEMPTS = 6
_DELAY_S = 4


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _document_text(document) -> str:
    if isinstance(document, str):
        return document
    if document is None:
        return ""
    try:
        return json.dumps(document)
    except (TypeError, ValueError):
        return str(document)


def _roles(snapshot) -> list:
    resources = (snapshot or {}).get("resources") or {}
    found = resources.get("AWS::IAM::Role") or {}
    if not isinstance(found, dict):
        return []
    return [props for props in found.values() if isinstance(props, dict)]


def _rules(snapshot) -> list:
    resources = (snapshot or {}).get("resources") or {}
    found = resources.get("AWS::Events::Rule") or {}
    if not isinstance(found, dict):
        return []
    return [props for props in found.values() if isinstance(props, dict)]


def _pattern_text(props) -> str:
    pattern = props.get("EventPattern")
    if isinstance(pattern, str):
        return pattern
    if pattern is None:
        return ""
    try:
        return json.dumps(pattern)
    except (TypeError, ValueError):
        return str(pattern)


def _target_function(arn) -> str:
    if not isinstance(arn, str) or ":function:" not in arn:
        return ""
    return arn.split(":function:", 1)[1].split(":")[0]


def _identities_still_shared(snapshot) -> bool:
    """The scanner's execution identity still admits the event service while something now
    carries EC2 image events to the scanner."""
    shared = False
    for props in _roles(snapshot):
        if str(props.get("RoleName") or "") != SCAN_ROLE:
            continue
        shared = EVENT_SERVICE in _document_text(props.get("AssumeRolePolicyDocument"))
    if not shared:
        return False
    for props in _rules(snapshot):
        pattern = _pattern_text(props)
        if "aws.ec2" not in pattern or not any(name in pattern for name in EVENT_NAMES):
            continue
        targets = props.get("Targets")
        if not isinstance(targets, list):
            continue
        if any(_target_function(t.get("Arn")) == SCANNER for t in targets if isinstance(t, dict)):
            return True
    return False


def _retry(call, **kwargs):
    """A freshly created identity is not assumable at once: EventBridge refuses a rule that runs
    as it until the trust has propagated. Keep trying, and let a rule that stays refused stand as
    it is rather than losing the rest of the intent."""
    for attempt in range(_ATTEMPTS):
        try:
            return call(**kwargs)
        except Exception:  # noqa: BLE001 - propagation, or a rule that cannot take this identity
            if attempt < _ATTEMPTS - 1:
                time.sleep(_DELAY_S)
    return None


@distract(
    role="identity administrator",
    responsibility="owns workload identities and which workload runs as which",
    intent=("event delivery runs as its own identity: image_event_delivery_role is what rules "
            "carrying EC2 image events run as, and image_scan_role is only what the image "
            "scanner runs as — assumable by the function service alone"),
    api=on_api("events", "PutTargets", phase="after_success"),
    release="after_completed",
    predicate=_identities_still_shared,
    resolution=("An identity is only what its workload runs as. What carries events runs as its "
                "own, never as a workload's."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    iam = boto3.client("iam", region_name=region)
    events = boto3.client("events", region_name=region)

    try:
        delivery_arn = iam.get_role(RoleName=DELIVERY_ROLE)["Role"]["Arn"]
        created = False
    except Exception:  # noqa: BLE001 - the delivery identity is not in the account yet
        delivery_arn = iam.create_role(RoleName=DELIVERY_ROLE,
                                       AssumeRolePolicyDocument=DELIVERY_TRUST,
                                       Description=DELIVERY_DESCRIPTION)["Role"]["Arn"]
        created = True

    # A settling window before the rest is written, so the identities being taken apart arrive
    # as an event of their own — and so a freshly created identity has propagated before a rule
    # is given it to run as.
    time.sleep(_SETTLE_S)

    narrowed = False
    try:
        scan = iam.get_role(RoleName=SCAN_ROLE)["Role"]
        if EVENT_SERVICE in _document_text(scan.get("AssumeRolePolicyDocument")):
            iam.update_assume_role_policy(RoleName=SCAN_ROLE, PolicyDocument=SCAN_TRUST)
            narrowed = True
    except Exception:  # noqa: BLE001 - the scanner's identity is not there to narrow
        pass

    given: list[str] = []
    for rule in events.list_rules().get("Rules", []):
        name = str(rule.get("Name") or "")
        if not name or rule.get("ManagedBy"):
            continue
        pattern = str(rule.get("EventPattern") or "")
        if "aws.ec2" not in pattern or not any(term in pattern for term in EVENT_NAMES):
            continue
        if str(rule.get("RoleArn") or "") == delivery_arn:
            continue
        request = {"Name": name, "EventPattern": pattern, "RoleArn": delivery_arn,
                   "State": str(rule.get("State") or "ENABLED")}
        description = str(rule.get("Description") or "")
        if description:
            request["Description"] = description
        if _retry(events.put_rule, **request) is not None:
            given.append(name)

    # Fingerprint: the delivery identity. It comes back from the events:ListRules / DescribeRule
    # that asks what this account watches for — it is the identity those rules now run as — and
    # from any listing of the account's roles.
    return {"delivery_role": DELIVERY_ROLE, "created": created, "narrowed": narrowed,
            "rules_given": given, "fingerprint": [DELIVERY_ROLE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
