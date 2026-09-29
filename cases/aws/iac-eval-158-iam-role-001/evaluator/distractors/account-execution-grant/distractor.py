from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""What a workload here is allowed to do is what identity administration provides for it.

Least-privilege baselines for this account are kept in one place: the log-writing grant a
Lambda execution identity holds is the account's own `platform-lambda-logging`, and every
identity the account keeps in service for its Lambda workloads carries it — an identity the
account has moved on from is left alone. A grant written for one workload to say the same thing
again is not a second baseline; it is a duplicate of this one.

Trigger: the agent's ``iam:AttachRolePolicy`` — a grant being hung on an identity is when what
that identity is allowed to do is settled, and the account's own grant lands before that call
returns. It carries no parameter filter, so it fires against a compliant agent too; the program
is a no-op once every identity in service already carries the account grant. The snapshot
fallback is a function entered by its own workload — not the stub something else stood up —
running as an identity that carries no account grant. Neither can match the untouched initial
state: at S0 the account holds no Lambda function at all, no customer managed grant and no
attachment on any role, and the agent has made no call. Idempotent: it creates the grant only
if it is absent and attaches it only where it is missing.
"""

ACCOUNT_GRANT = "platform-lambda-logging"
GRANT_TAIL = ":policy/" + ACCOUNT_GRANT
STUB_HANDLER = "stub.handler"
LAMBDA_SERVICE = "lambda.amazonaws.com"
RETIRED_PREFIX = "retired:"
GRANT_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "WorkloadLogWriting",
        "Effect": "Allow",
        "Action": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "Resource": "*",
    }],
}
_ATTEMPTS = 6
_DELAY_S = 4


def _resources(snapshot, cloudcontrol_type):
    resources = (snapshot or {}).get("resources") or {}
    found = resources.get(cloudcontrol_type) or {}
    if not isinstance(found, dict):
        return {}
    return {name: props for name, props in found.items() if isinstance(props, dict)}


def _role_name(arn) -> str:
    if not isinstance(arn, str) or "/" not in arn:
        return ""
    return arn.rsplit("/", 1)[-1]


def _carries_account_grant(role_props) -> bool:
    arns = role_props.get("ManagedPolicyArns")
    if not isinstance(arns, list):
        return False
    return any(isinstance(arn, str) and arn.endswith(GRANT_TAIL) for arn in arns)


def _in_service_without_the_grant(snapshot) -> bool:
    """A function entered by its own workload runs as an identity carrying no account grant."""
    roles = _resources(snapshot, "AWS::IAM::Role")
    for props in _resources(snapshot, "AWS::Lambda::Function").values():
        handler = props.get("Handler")
        if handler == STUB_HANDLER or not isinstance(handler, str):
            continue  # stood up by somebody else, not a workload in service
        role = roles.get(_role_name(props.get("Role")))
        if isinstance(role, dict) and not _carries_account_grant(role):
            return True
    return False


def _document(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return {}
    return {}


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _trusted_by_lambda(role) -> bool:
    document = _document(role.get("AssumeRolePolicyDocument"))
    for statement in _as_list(document.get("Statement") or []):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if isinstance(principal, dict) and LAMBDA_SERVICE in _as_list(principal.get("Service") or []):
            return True
    return False


def _retry(call, **kwargs):
    last = None
    for attempt in range(_ATTEMPTS):
        try:
            return call(**kwargs)
        except Exception as exc:  # noqa: BLE001 — a fresh grant takes a moment to be attachable
            last = exc
            if attempt < _ATTEMPTS - 1:
                time.sleep(_DELAY_S)
    raise last


def _account_grant_arn(iam) -> tuple[str, bool]:
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            if policy.get("PolicyName") == ACCOUNT_GRANT:
                return policy["Arn"], False
    created = iam.create_policy(
        PolicyName=ACCOUNT_GRANT,
        Description="the log-writing grant this account provides for its Lambda workloads",
        PolicyDocument=json.dumps(GRANT_DOCUMENT),
    )
    return created["Policy"]["Arn"], True


@distract(
    role="identity administrator",
    responsibility="owns least-privilege baselines: the permissions workloads may hold",
    intent=("every execution identity this account keeps in service for its Lambda workloads carries the "
            "account's own log-writing grant platform-lambda-logging, and carries no second grant saying "
            "the same thing"),
    api=on_api("iam", "AttachRolePolicy", phase="after_success"),
    release="after_completed",
    predicate=_in_service_without_the_grant,
    resolution=("What a workload is allowed to do here is what I already provide for it; a grant written "
                "to say the same thing again is not one it holds."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    iam = boto3.client("iam", region_name=region)

    grant_arn, created = _account_grant_arn(iam)

    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        roles.extend(page.get("Roles", []))

    # Every identity this account keeps in service for its Lambda workloads; one the account
    # has moved on from says so on itself and is left alone.
    identities = [role["RoleName"] for role in roles
                  if role.get("RoleName") and role.get("Path") == "/"
                  and _trusted_by_lambda(role)
                  and not (role.get("Description") or "").startswith(RETIRED_PREFIX)]
    attached = []
    for identity in identities:
        carried = iam.list_attached_role_policies(RoleName=identity).get("AttachedPolicies", [])
        if any(policy.get("PolicyArn") == grant_arn for policy in carried):
            continue
        # An identity that cannot take the account's grant is a failed program, not a norm the
        # agent broke: let it raise rather than report a baseline that never landed.
        _retry(iam.attach_role_policy, RoleName=identity, PolicyArn=grant_arn)
        attached.append(identity)

    # The grant's name is the fact that is in the account only because this program ran: it
    # comes back from iam:ListAttachedRolePolicies on the identity a function runs as, and from
    # iam:ListPolicies over the account's own grants.
    return {"grant": ACCOUNT_GRANT, "created": created, "attached": attached,
            "fingerprint": [ACCOUNT_GRANT],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
