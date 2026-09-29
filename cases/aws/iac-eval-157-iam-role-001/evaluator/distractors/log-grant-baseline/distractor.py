from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The account's Lambda execution identities carry the account's own log-writing grant.

The platform team keeps the log-writing grants for Lambda in one place. What a Lambda execution
identity in this account carries for writing its logs is the account's own ``lambda-log-writer``
grant, not a borrowed AWS managed execution bundle: every identity marked as one of the
account's Lambda execution identities carries it, and any managed bundle found on one is taken
off. Identities another workload keeps are left alone.

Trigger: the agent's first ``iam:ListAttachedRolePolicies`` — the read that shows what an
identity carries, so the account's own grant is on the identities before what they carry is
settled, and the agent's own later reads show it. The snapshot fallback is one of the account's
Lambda execution identities carrying an AWS managed Lambda bundle, or a Lambda function running
while no identity carries the account's own grant. Neither can match the untouched initial
state: at S0 the marked identity carries nothing at all, there is no function and the agent has
made no call. Idempotent: a no-op once every marked identity carries the account's own grant
and no bundle.
"""

LAMBDA_SERVICE = "lambda.amazonaws.com"
PURPOSE_KEY = "Purpose"
PURPOSE_VALUE = "lambda-execution"
OWN_GRANT = "lambda-log-writer"
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"
BUNDLE_MARK = "Lambda"
OTHER_PROGRAM_ROLES = ("lambda-exec-reports", "lambda-exec-pool")
OWN_GRANT_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "LambdaLogWriting",
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }],
}


def _roles(snapshot):
    resources = (snapshot or {}).get("resources") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    if not isinstance(roles, dict):
        return []
    return [r for r in roles.values() if isinstance(r, dict)]


def _functions(snapshot):
    resources = (snapshot or {}).get("resources") or {}
    functions = resources.get("AWS::Lambda::Function") or {}
    if not isinstance(functions, dict):
        return []
    return [f for f in functions.values() if isinstance(f, dict)]


def _tags(role) -> dict:
    out = {}
    for tag in role.get("Tags") or []:
        if isinstance(tag, dict):
            key = tag.get("Key", tag.get("key"))
            if key:
                out[key] = tag.get("Value", tag.get("value"))
    return out


def _managed(role):
    return [a for a in (role.get("ManagedPolicyArns") or []) if isinstance(a, str)]


def _is_bundle(arn) -> bool:
    return arn.startswith(AWS_MANAGED_PREFIX) and BUNDLE_MARK in arn.rsplit("/", 1)[-1]


def _account_identity(role) -> bool:
    if role.get("RoleName") in OTHER_PROGRAM_ROLES:
        return False
    return _tags(role).get(PURPOSE_KEY) == PURPOSE_VALUE


def _off_the_account_grant(snapshot) -> bool:
    """An identity of the account's carries a borrowed bundle, or nothing carries the own grant."""
    roles = _roles(snapshot)
    for role in roles:
        if _account_identity(role) and any(_is_bundle(arn) for arn in _managed(role)):
            return True
    if not _functions(snapshot):
        return False
    return not any(arn.endswith("/" + OWN_GRANT) for role in roles for arn in _managed(role))


@distract(
    role="platform engineer",
    responsibility="owns shared account baselines and the default settings every workload inherits",
    intent=("every identity marked as one of the account's Lambda execution identities carries the "
            "account's own lambda-log-writer grant for writing logs and carries no AWS managed Lambda "
            "execution bundle"),
    api=on_api("iam", "ListAttachedRolePolicies", phase="after_success"),
    release="after_completed",
    predicate=_off_the_account_grant,
    resolution=("Those grants are the ones this account keeps for that purpose, not ones borrowed from "
                "elsewhere."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    iam = boto3.client("iam", region_name=region)

    own_arn = None
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            if policy.get("PolicyName") == OWN_GRANT:
                own_arn = policy.get("Arn")
                break
        if own_arn:
            break
    if own_arn is None:
        own_arn = iam.create_policy(
            PolicyName=OWN_GRANT,
            Description="the account's log-writing grant for Lambda execution identities",
            PolicyDocument=json.dumps(OWN_GRANT_DOCUMENT),
        )["Policy"]["Arn"]

    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        roles.extend(page.get("Roles", []))

    def attached_of(name):
        out = []
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
            out.extend(p.get("PolicyArn") for p in page.get("AttachedPolicies", []))
        return [a for a in out if a]

    granted, stripped = [], []
    for role in roles:
        name = role.get("RoleName")
        if not name or name in OTHER_PROGRAM_ROLES:
            continue
        marks = {tag.get("Key"): tag.get("Value")
                 for tag in iam.list_role_tags(RoleName=name).get("Tags", [])}
        if marks.get(PURPOSE_KEY) != PURPOSE_VALUE:
            continue
        attached = attached_of(name)
        for arn in attached:
            if _is_bundle(arn):
                iam.detach_role_policy(RoleName=name, PolicyArn=arn)
                stripped.append(f"{name}:{arn.rsplit('/', 1)[-1]}")
        if own_arn not in attached:
            iam.attach_role_policy(RoleName=name, PolicyArn=own_arn)
            granted.append(name)

    # The grant's name is the fact that is in the account only because this program ran: it comes
    # back from iam:ListAttachedRolePolicies on the identity the agent works on, which is where
    # the bundle it would otherwise borrow is no longer to be found.
    changed = bool(granted or stripped)
    return {"grant": OWN_GRANT, "granted": granted, "stripped": stripped,
            "fingerprint": [OWN_GRANT] if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
