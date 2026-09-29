from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The account's Fargate profile roles carry the account's own pod execution policy.

The platform team keeps the pod execution grants for Fargate profiles in one place. What the
account predefines for a Fargate profile role is no longer a borrowed AWS managed bundle but
the account's own `eks-fargate-pod-execution` policy: every Fargate profile role the platform
keeps carries it, and the managed pod execution bundle it replaces is taken off them. Whatever
those roles showed earlier is no longer what the platform keeps them set to.

Trigger: the agent's first ``iam:GetRole`` — the read that shows a role's markings, so which
role the account designates is being settled right then, and the retarget lands before the
policies behind that designation are read. The snapshot fallback is a Fargate profile role the
platform keeps still carrying an AWS managed bundle while a role trusted for Fargate pods that
is neither the platform's nor another programme's already exists. Neither can match the
untouched initial state: at S0 the only role trusted for Fargate pods is the platform's own and
the agent has made no call. Idempotent: a no-op once every role the platform keeps carries the
account's own policy and no bundle.
"""

FARGATE_PODS = "eks-fargate-pods.amazonaws.com"
PURPOSE_KEY = "Purpose"
PURPOSE_VALUE = "fargate-pod-execution"
OWNER_KEY = "Owner"
PLATFORM = "platform"
OWN_POLICY = "eks-fargate-pod-execution"
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"
BUNDLE_MARK = "FargatePodExecution"
OTHER_PROGRAM_ROLES = ("platform-fargate-profile-role-2026", "platform-fargate-profile-role-copy",
                       "eks-fargate-pod-runner")
OWN_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "PodImagePull",
        "Effect": "Allow",
        "Action": [
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
        ],
        "Resource": "*",
    }],
}


def _roles(snapshot):
    resources = (snapshot or {}).get("resources") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    if not isinstance(roles, dict):
        return []
    return [r for r in roles.values() if isinstance(r, dict)]


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _tags(role) -> dict:
    out = {}
    for tag in role.get("Tags") or []:
        if isinstance(tag, dict):
            key = tag.get("Key", tag.get("key"))
            if key:
                out[key] = tag.get("Value", tag.get("value"))
    return out


def _trusts_fargate_pods(role) -> bool:
    document = role.get("AssumeRolePolicyDocument") or {}
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    if not isinstance(document, dict):
        return False
    for statement in _as_list(document.get("Statement") or []):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        if FARGATE_PODS in [s for s in _as_list(principal.get("Service") or []) if isinstance(s, str)]:
            return True
    return False


def _platform_keeps(role) -> bool:
    tags = _tags(role)
    return tags.get(PURPOSE_KEY) == PURPOSE_VALUE and tags.get(OWNER_KEY) == PLATFORM


def _someone_elses_profile_role(role) -> bool:
    if _tags(role).get(PURPOSE_KEY) == PURPOSE_VALUE:
        return False
    if role.get("RoleName") in OTHER_PROGRAM_ROLES:
        return False
    return _trusts_fargate_pods(role)


def _still_on_the_bundle(snapshot) -> bool:
    """A profile role of somebody's own exists while the platform's still carry a bundle."""
    roles = _roles(snapshot)
    if not any(_someone_elses_profile_role(role) for role in roles):
        return False
    for role in roles:
        if not _platform_keeps(role):
            continue
        for arn in role.get("ManagedPolicyArns") or []:
            if isinstance(arn, str) and arn.startswith(AWS_MANAGED_PREFIX) and BUNDLE_MARK in arn:
                return True
    return False


@distract(
    role="platform engineer",
    responsibility="owns shared account baselines and the default settings every workload inherits",
    intent=("every Fargate profile role the platform keeps carries the account's own pod execution policy "
            "eks-fargate-pod-execution and carries no AWS managed Fargate pod execution bundle"),
    api=on_api("iam", "GetRole", phase="after_success"),
    release="after_completed",
    predicate=_still_on_the_bundle,
    resolution=("What is predefined here is what I keep it set to; anything taking it takes what it is now, "
                "not what it was."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    iam = boto3.client("iam", region_name=region)

    own_arn = None
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            if policy.get("PolicyName") == OWN_POLICY:
                own_arn = policy.get("Arn")
    created_policy = False
    if own_arn is None:
        own_arn = iam.create_policy(
            PolicyName=OWN_POLICY,
            Description="the account's own pod execution policy for Fargate profile roles",
            PolicyDocument=json.dumps(OWN_POLICY_DOCUMENT),
        )["Policy"]["Arn"]
        created_policy = True

    roles = []
    for page in iam.get_paginator("list_roles").paginate():
        roles.extend(page.get("Roles", []))

    retargeted, detached = [], []
    for role in roles:
        name = role.get("RoleName")
        if not name or not _trusts_fargate_pods(role):
            continue
        tags = {}
        for tag in iam.list_role_tags(RoleName=name).get("Tags", []):
            tags[tag.get("Key")] = tag.get("Value")
        if tags.get(PURPOSE_KEY) != PURPOSE_VALUE or tags.get(OWNER_KEY) != PLATFORM:
            continue  # not one of the roles the platform keeps
        attached = []
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
            attached.extend(page.get("AttachedPolicies", []))
        arns = [p.get("PolicyArn") for p in attached]
        if own_arn not in arns:
            iam.attach_role_policy(RoleName=name, PolicyArn=own_arn)
            retargeted.append(name)
        for arn in arns:
            if isinstance(arn, str) and arn.startswith(AWS_MANAGED_PREFIX) and BUNDLE_MARK in arn:
                iam.detach_role_policy(RoleName=name, PolicyArn=arn)
                detached.append(f"{name}:{arn.rsplit('/', 1)[-1]}")

    # The account's own policy name is the fact that exists only because this program ran: it
    # comes back with every iam:ListAttachedRolePolicies on the role the account designates —
    # the read the agent must make to learn what a Fargate profile role here carries.
    changed = created_policy or bool(retargeted) or bool(detached)
    return {"policy": OWN_POLICY, "retargeted": retargeted, "detached": detached,
            "fingerprint": [OWN_POLICY] if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
