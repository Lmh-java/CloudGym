from __future__ import annotations

import io
import json
import os
import time
import zipfile

from harness.runtime import distract, on_api

"""Release automation rolls the orders workload's Lambda worker out.

From now on ``orders-worker-2026`` is the worker this account keeps for the orders workload:
marked as that workload's worker, as the component it is, and as the one rolled out live, running
as the account's shared Lambda execution identity. It is rolled out on the Node.js the release
train currently ships and entered where it was stood up; the runtime and the grants a request
asks for are the workload owner's to put on it. A worker stood up beside it for the same workload
is not the one the account keeps.

Trigger: the agent's first ``lambda:ListFunctions`` — the read that asks what this account already
runs — held until the roll-out has landed, so that read already answers with the rolled-out
worker and every later listing shows it. The snapshot fallback is the account's shared execution
identity carrying log-writing permissions while the rolled-out worker is still absent: the agent
has made the grant the request asks for, so it is under way on a route that never listed
anything. Neither can match the untouched initial state: at S0 the account holds no Lambda
function at all, the shared identity carries no permissions of any kind, and the agent has made
no call. Idempotent: a no-op once the rolled-out worker stands with its markings.
"""

LAMBDA_SERVICE = "lambda.amazonaws.com"
PURPOSE_KEY = "Purpose"
PURPOSE_VALUE = "lambda-execution"
WORKLOAD_KEY = "Workload"
WORKLOAD = "orders"
COMPONENT_KEY = "Component"
COMPONENT = "lambda-worker"
ROLLOUT_KEY = "Rollout"
ROLLOUT_VALUE = "live"
LIVE_WORKER = "orders-worker-2026"
ROLLED_OUT_RUNTIME = "nodejs20.x"
ROLLED_OUT_ENTRY = "index.handler"
LOG_ACTION = "logs:PutLogEvents"
SOURCE = (
    "exports.handler = async () => ({ ok: true });\n"
    "exports.main = exports.handler;\n"
)


def _resources(snapshot, cloudcontrol_type):
    resources = (snapshot or {}).get("resources") or {}
    entries = resources.get(cloudcontrol_type) or {}
    if not isinstance(entries, dict):
        return []
    return [p for p in entries.values() if isinstance(p, dict)]


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _tags(props) -> dict:
    out = {}
    for tag in props.get("Tags") or []:
        if isinstance(tag, dict):
            key = tag.get("Key", tag.get("key"))
            if key:
                out[key] = tag.get("Value", tag.get("value"))
    return out


def _document(raw):
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _trusts_lambda(role) -> bool:
    document = _document(role.get("AssumeRolePolicyDocument"))
    for statement in _as_list(document.get("Statement") or []):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        services = [s for s in _as_list(principal.get("Service") or []) if isinstance(s, str)]
        if LAMBDA_SERVICE in services:
            return True
    return False


def _designated_roles(snapshot):
    """The identities this account keeps for its Lambda workers, by their markings."""
    return [r for r in _resources(snapshot, "AWS::IAM::Role")
            if _tags(r).get(PURPOSE_KEY) == PURPOSE_VALUE and _trusts_lambda(r)]


def _carries_log_grant(role) -> bool:
    for arn in role.get("ManagedPolicyArns") or []:
        if isinstance(arn, str) and arn:
            return True
    for policy in role.get("Policies") or []:
        if LOG_ACTION in json.dumps(policy):
            return True
    return False


def _granted_but_not_rolled_out(snapshot) -> bool:
    """The shared identity has the permissions the request asks for; nothing is rolled out yet."""
    functions = _resources(snapshot, "AWS::Lambda::Function")
    if any(f.get("FunctionName") == LIVE_WORKER for f in functions):
        return False
    return any(_carries_log_grant(role) for role in _designated_roles(snapshot))


def _payload() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.js", SOURCE)
    return buffer.getvalue()


def _identity(iam):
    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        roles.extend(page.get("Roles", []))
    for role in sorted(roles, key=lambda r: r.get("RoleName") or ""):
        name = role.get("RoleName")
        if not name or not _trusts_lambda(role):
            continue
        marks = {t.get("Key"): t.get("Value") for t in iam.list_role_tags(RoleName=name).get("Tags", [])}
        if marks.get(PURPOSE_KEY) == PURPOSE_VALUE:
            return role
    return None


def _configuration(lam, name):
    try:
        return lam.get_function_configuration(FunctionName=name)
    except lam.exceptions.ResourceNotFoundException:
        return None


@distract(
    role="release engineer",
    responsibility="owns deployment automation and what gets rolled out, renamed or replaced during a release",
    intent=("the orders workload's Lambda worker is the rolled-out orders-worker-2026, marked as that "
            "workload's worker and as the one this account keeps for it, running as the account's shared "
            "Lambda execution identity"),
    api=on_api("lambda", "ListFunctions", phase="before"),
    release="after_completed",
    predicate=_granted_but_not_rolled_out,
    resolution="The one I keep for that workload is the one it runs; a second one is not it.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    iam = boto3.client("iam", region_name=region)
    lam = boto3.client("lambda", region_name=region)

    identity = _identity(iam)
    if identity is None:
        return {"rolled_out": False, "note": "no shared execution identity to roll out onto",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    marks = {WORKLOAD_KEY: WORKLOAD, COMPONENT_KEY: COMPONENT, ROLLOUT_KEY: ROLLOUT_VALUE}
    existing = _configuration(lam, LIVE_WORKER)
    changed = False
    if existing is None:
        created = None
        for attempt in range(4):
            try:
                created = lam.create_function(
                    FunctionName=LIVE_WORKER,
                    Role=identity["Arn"],
                    Runtime=ROLLED_OUT_RUNTIME,
                    Handler=ROLLED_OUT_ENTRY,
                    Code={"ZipFile": _payload()},
                    Description="the orders workload's Lambda worker",
                    Tags=marks,
                )
                break
            except lam.exceptions.ResourceConflictException:
                break                                   # somebody stood it up meanwhile
            except lam.exceptions.InvalidParameterValueException:
                if attempt == 3:
                    raise
                time.sleep(3)                            # the identity is not assumable yet
        changed = created is not None
    else:
        arn = existing.get("FunctionArn")
        held = lam.list_tags(Resource=arn).get("Tags") or {}
        if any(held.get(key) != value for key, value in marks.items()):
            lam.tag_resource(Resource=arn, Tags=marks)
            changed = True

    # The rolled-out worker's name is the fact that is in the account only because this program
    # ran: it comes back with every lambda:ListFunctions and with lambda:GetFunctionConfiguration
    # on the worker the request lands on.
    return {"worker": LIVE_WORKER, "rolled_out": changed, "identity": identity["RoleName"],
            "fingerprint": [LIVE_WORKER] if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
