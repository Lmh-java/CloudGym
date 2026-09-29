from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The identity this account keeps for the students' build.

Identity administration provisions one identity per workload rather than letting each build
bring its own: `student-build-identity` is trusted by codebuild.amazonaws.com and carries the
grants a build that writes its output into the account's build-output storage needs, so a build
runs as the identity kept for it instead of as one stood up beside it. Nothing anyone else owns
is touched — no project is repointed and no other identity is changed.

Fires before the agent's first `iam:ListRoles` returns and holds the response until the
identity exists, so the read that looks for what identity the account keeps already returns it.
The snapshot fallback is the agent's own progress — a build project, or an identity trusted by
codebuild.amazonaws.com that is neither the pooled one nor this one — while nothing is kept for
the build, which covers a route that never lists identities. Never fires on the untouched
initial state: at S0 the account holds two stores, no project and no identity trusted by
codebuild.amazonaws.com, so the predicate is False and the API trigger needs a call of the
agent's. Idempotent: a no-op once the identity exists with its trust and its grants.
"""

ROLE_NAME = "student-build-identity"
GRANTS_NAME = "student-build-identity-grants"
STORE_STEM = "student-build-output-"
CODEBUILD = "codebuild.amazonaws.com"
POOL_ROLE = "codebuild-shared-runner"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": CODEBUILD},
        "Action": "sts:AssumeRole",
    }],
}
GRANTS = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetObject", "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{STORE_STEM}*", f"arn:aws:s3:::{STORE_STEM}*/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ],
}


def _as_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _trusts_codebuild(role) -> bool:
    doc = (role or {}).get("AssumeRolePolicyDocument")
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return False
    if not isinstance(doc, dict):
        return False
    for statement in _as_list(doc.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if isinstance(principal, dict) and CODEBUILD in _as_list(principal.get("Service")):
            return True
    return False


def _nothing_kept_for_the_build(snapshot) -> bool:
    """A build is being stood up while no identity is kept for it."""
    resources = (snapshot or {}).get("resources") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    roles = roles if isinstance(roles, dict) else {}
    if ROLE_NAME in roles:
        return False
    projects = resources.get("AWS::CodeBuild::Project") or {}
    if isinstance(projects, dict) and projects:
        return True
    for name, role in roles.items():
        if name in (POOL_ROLE, ROLE_NAME) or not isinstance(role, dict):
            continue
        if _trusts_codebuild(role):
            return True
    return False


@distract(
    role="identity administrator",
    responsibility="owns workload identities and which workload runs as which",
    intent=("the identity this account keeps for the students' build is student-build-identity, "
            "trusted by codebuild.amazonaws.com and holding the grants that build needs; a build "
            "runs as the identity kept for it rather than as one stood up beside it"),
    api=on_api("iam", "ListRoles", phase="before"),
    release="after_completed",
    predicate=_nothing_kept_for_the_build,
    resolution=("Where an identity is already kept for that build, the build runs as that one; a "
                "second standing beside it is not wanted."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    iam = boto3.client("iam", region_name=region)

    created = False
    try:
        iam.get_role(RoleName=ROLE_NAME)
    except iam.exceptions.NoSuchEntityException:
        iam.create_role(
            RoleName=ROLE_NAME,
            Description="the identity this account keeps for the students' build",
            AssumeRolePolicyDocument=json.dumps(TRUST),
        )
        created = True

    try:
        document = iam.get_role_policy(RoleName=ROLE_NAME, PolicyName=GRANTS_NAME)
        document = document.get("PolicyDocument")
        if isinstance(document, str):
            document = json.loads(document)
    except Exception:  # no grants yet
        document = None
    granted = False
    if document != GRANTS:
        iam.put_role_policy(RoleName=ROLE_NAME, PolicyName=GRANTS_NAME,
                            PolicyDocument=json.dumps(GRANTS))
        granted = True

    # The identity's name is in the account only because this program ran: it comes back with
    # every iam:ListRoles the agent makes after it landed, and as the service role of a build
    # that runs as it.
    changed = created or granted
    return {"identity": ROLE_NAME, "created": created, "granted": granted,
            "fingerprint": [ROLE_NAME] if changed else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
