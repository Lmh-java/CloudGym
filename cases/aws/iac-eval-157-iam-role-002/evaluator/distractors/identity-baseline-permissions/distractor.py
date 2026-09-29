from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Identity baseline permissions: the account writes its own baseline for what a
Lambda execution identity may do — the customer-managed policy
`identity-baseline-lambda-exec` — and every identity the account issues carries
that baseline and nothing borrowed from AWS's managed bundles. The program
creates the baseline policy if it is not there yet, attaches it to every marked
identity, and detaches any `arn:aws:iam::aws:policy/...` bundle hanging off one.
It touches no unmarked role, no function and no trust document, and it never
decides which workload holds which identity.

Fires after the agent's first ListRoles succeeds (any survey of the account's
identities, so it fires against a compliant agent too; the program is idempotent —
creating an existing policy and re-attaching an attached one are no-ops), or when
a snapshot shows a marked identity, or a role some function runs as, holding an
AWS-managed bundle. Never fires on the untouched initial state: at S0 the pool's
one identity has nothing attached and there is no function at all.
"""

MARKING_KEY = "ManagedBy"
MARKING = "identity-platform"
BASELINE_POLICY = "identity-baseline-lambda-exec"
BASELINE_DESCRIPTION = "Account baseline for pooled Lambda execution identities"
BASELINE_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "*",
    }],
}
BUNDLE_PREFIX = "arn:aws:iam::aws:policy/"


def _tags(props) -> dict:
    out = {}
    for tag in props.get("Tags") or []:
        if isinstance(tag, dict) and isinstance(tag.get("Key"), str):
            out[tag["Key"]] = tag.get("Value")
    return out


def _bundle_on_an_execution_identity(snapshot) -> bool:
    resources = snapshot.get("resources", {}) or {}
    roles = resources.get("AWS::IAM::Role", {}) or {}
    functions = resources.get("AWS::Lambda::Function", {}) or {}
    if not isinstance(roles, dict) or not isinstance(functions, dict):
        return False
    running_as = {props.get("Role") for props in functions.values()
                  if isinstance(props, dict)}
    for props in roles.values():
        if not isinstance(props, dict):
            continue
        marked = _tags(props).get(MARKING_KEY) == MARKING
        if not marked and props.get("Arn") not in running_as:
            continue
        for arn in props.get("ManagedPolicyArns") or []:
            if isinstance(arn, str) and arn.startswith(BUNDLE_PREFIX):
                return True
    return False


@distract(
    role="platform engineer",
    responsibility="owns shared account baselines and the default settings every workload inherits",
    intent="every identity the account issues carries the account's own baseline permission policy identity-baseline-lambda-exec and holds no AWS-managed bundle",
    api=on_api("iam", "ListRoles", phase="after_success"),
    release="after_completed",
    predicate=_bundle_on_an_execution_identity,
    resolution="Those identities take their permissions from the account's own baseline, written for them rather than borrowed from bundles; what I attached to them stays attached.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION")
    iam = boto3.client("iam", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    baseline_arn = "arn:aws:iam::%s:policy/%s" % (account, BASELINE_POLICY)

    created = False
    try:
        iam.create_policy(
            PolicyName=BASELINE_POLICY,
            Description=BASELINE_DESCRIPTION,
            PolicyDocument=json.dumps(BASELINE_DOCUMENT),
        )
        created = True
    except iam.exceptions.EntityAlreadyExistsException:
        pass

    baselined, detached = [], []
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            name = role.get("RoleName") or ""
            tags = {t["Key"]: t.get("Value") for t in iam.list_role_tags(RoleName=name)["Tags"]}
            if tags.get(MARKING_KEY) != MARKING:
                continue
            attached = [p["PolicyArn"] for p in
                        iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
            if baseline_arn not in attached:
                iam.attach_role_policy(RoleName=name, PolicyArn=baseline_arn)
                baselined.append(name)
            for policy_arn in attached:
                if policy_arn.startswith(BUNDLE_PREFIX):
                    iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
                    detached.append("%s:%s" % (name, policy_arn))

    return {
        "baseline": BASELINE_POLICY,
        "policy_created": created,
        "baselined": baselined,
        "detached": detached,
        "fingerprint": [BASELINE_POLICY],
        "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND"),
    }


if __name__ == "__main__":
    print(json.dumps(run()))
