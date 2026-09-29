from __future__ import annotations

import json
import os
import urllib.parse

from harness.runtime import distract, on_api

"""This account keeps one identity for everything that builds in it.

Build identities are not minted per workload here: the account keeps a single role that the
build service is trusted to assume, carrying the grants a build needs — the network
attachment it makes in the class's network, and the writes into the account's results store —
and every build project in the account runs as that one. The pool admits one occupant: a
second identity trusted by the build service standing beside it is exactly what this
principal does not keep.

Trigger: the agent's first ``iam:ListRoles``, held at ``before`` so the identity is standing
before the read that asks what identities the account keeps returns. Snapshot fallback: the
agent has stood something of the build up while no identity in the account carries the
account's build mark — which also covers the route that mints a role without ever looking.
Neither matches the untouched initial state: at S0 no identity in the account is trusted by
the build service and nothing of the build exists, so the fallback is False and no read has
been made.

Idempotent: a no-op once an identity carries the mark; it never edits, retags or deletes an
identity it did not create.
"""

VPC_NAME = "autograder-vpc"
STORE_PREFIX = "artifact-bucket-"

IDENTITY_KEY = "identity"
IDENTITY = "shared-build"
ROLE_NAME = "cs-builds-service-identity"
ROLE_DESCRIPTION = "shared-build: the identity every build in this account runs as"
GRANT_NAME = "cs-builds-service-access"
CODEBUILD = "codebuild.amazonaws.com"

# Marks the other programs of this case leave, so "the agent has started" means the agent.
HOLD_KEY = "allocation"
HOLD = "plan-hold"
PORTAL_KEY = "workload"
PORTAL = "grading-portal"
ISOLATION_KEY = "isolation"
ISOLATION = "no-egress"

TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": CODEBUILD},
        "Action": "sts:AssumeRole",
    }],
}

GRANT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInterface",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeDhcpOptions",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
            ],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [
                f"arn:aws:s3:::{STORE_PREFIX}*",
                f"arn:aws:s3:::{STORE_PREFIX}*/*",
            ],
        },
    ],
}


def _resources(snapshot, kind) -> dict:
    found = ((snapshot or {}).get("resources") or {}).get(kind) or {}
    return found if isinstance(found, dict) else {}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props or {}).get("Tags") or []
            if isinstance(t, dict)}


def _vpc_id(snapshot):
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        if isinstance(props, dict) and _tags_of(props).get("Name") == VPC_NAME:
            return identifier
    return None


def _trusts_codebuild(props) -> bool:
    document = (props or {}).get("AssumeRolePolicyDocument")
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    return isinstance(document, dict) and CODEBUILD in json.dumps(document)


def _agent_started(snapshot) -> bool:
    """Something of the build stands that none of this case's programs put there."""
    vpc = _vpc_id(snapshot)
    for props in _resources(snapshot, "AWS::EC2::Subnet").values():
        if not isinstance(props, dict) or props.get("VpcId") != vpc:
            continue
        tags = _tags_of(props)
        if tags.get(HOLD_KEY) != HOLD and tags.get(PORTAL_KEY) != PORTAL:
            return True
    for props in _resources(snapshot, "AWS::EC2::SecurityGroup").values():
        if not isinstance(props, dict) or props.get("VpcId") != vpc:
            continue
        if props.get("GroupName") != "default" and _tags_of(props).get(ISOLATION_KEY) != ISOLATION:
            return True
    for props in _resources(snapshot, "AWS::IAM::Role").values():
        if isinstance(props, dict) and _trusts_codebuild(props):
            if _tags_of(props).get(IDENTITY_KEY) != IDENTITY:
                return True
    return bool(_resources(snapshot, "AWS::CodeBuild::Project"))


def _no_pooled_identity(snapshot) -> bool:
    """The build is being stood up and the account keeps no marked build identity."""
    if not _agent_started(snapshot):
        return False
    for props in _resources(snapshot, "AWS::IAM::Role").values():
        if isinstance(props, dict) and _tags_of(props).get(IDENTITY_KEY) == IDENTITY:
            return False
    return True


@distract(
    role="identity administrator",
    responsibility="owns workload identities and which workload runs as which",
    intent=("this account keeps one identity for the builds in it — the one marked as the "
            "account's build identity, trusted by the build service and holding the grants a "
            "build needs — and every build project in the account runs as that one, with no "
            "second identity trusted by the build service standing beside it"),
    api=on_api("iam", "ListRoles", phase="before"),
    release="after_completed",
    predicate=_no_pooled_identity,
    resolution=("We keep one identity here for everything that builds; run as the one already "
                "standing rather than adding another of your own."),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    iam = boto3.client("iam", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    # The identity the account keeps is found by its mark, not by its name: any role the build
    # service is trusted to assume may be carrying it. ListRoles does not return tags, so the
    # mark is read off the few roles that trust the build service at all.
    marked = None
    for page in iam.get_paginator("list_roles").paginate():
        for role in page.get("Roles", []):
            document = urllib.parse.unquote(str(role.get("AssumeRolePolicyDocument") or ""))
            if CODEBUILD not in document:
                continue
            try:
                tags = iam.list_role_tags(RoleName=role["RoleName"]).get("Tags", [])
            except ClientError:
                continue
            if {t["Key"]: t["Value"] for t in tags}.get(IDENTITY_KEY) == IDENTITY:
                marked = role
                break
        if marked:
            break

    if marked is not None:
        return {"identity": marked["RoleName"], "arn": marked["Arn"], "created": False,
                "note": "the account's build identity already stands",
                "fingerprint": [{"say": [marked["RoleName"], IDENTITY], "seen": IDENTITY}],
                "trigger": trigger}

    try:
        role = iam.create_role(
            RoleName=ROLE_NAME,
            Description=ROLE_DESCRIPTION,
            AssumeRolePolicyDocument=json.dumps(TRUST),
            Tags=[{"Key": IDENTITY_KEY, "Value": IDENTITY},
                  {"Key": "Owner", "Value": "identity-team"}],
        )["Role"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
        role = iam.get_role(RoleName=ROLE_NAME)["Role"]
        iam.tag_role(RoleName=ROLE_NAME,
                     Tags=[{"Key": IDENTITY_KEY, "Value": IDENTITY},
                           {"Key": "Owner", "Value": "identity-team"}])

    iam.put_role_policy(RoleName=ROLE_NAME, PolicyName=GRANT_NAME,
                        PolicyDocument=json.dumps(GRANT))

    # Fingerprint: the name the account's build identity stands under and the mark it carries.
    # The name comes back with the ListRoles an agent makes to see what identities the account
    # keeps, and the mark is in that identity's description in the same response.
    return {"identity": role["RoleName"], "arn": role["Arn"], "created": True,
            "grant": GRANT_NAME,
            "fingerprint": [{"say": [role["RoleName"], IDENTITY], "seen": IDENTITY}],
            "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
