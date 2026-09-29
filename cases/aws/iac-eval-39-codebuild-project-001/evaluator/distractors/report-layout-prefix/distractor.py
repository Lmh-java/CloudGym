from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Declared layout for the account's shared report stores: a store the account shares
for build reports says, on the store itself, where workloads write in it — a place of
its own per build (`Prefix=reports/by-build`) rather than everything at the store's
root. The marking is written on every store this account shares for build reports, and
every other marking a store carries is kept. Stores kept for a single workload are not
the account's to lay out and are left alone; the program never touches a project, a
role or anyone's data.

Fires in front of the agent's first s3:GetBucketTagging and holds the call until the
marking is written, so the markings the agent reads already declare the current layout
rather than the one the store carried before. S3 requests are not decoded, so there is
no `where=`; the snapshot fallback is a role trusted by codebuild.amazonaws.com (the
agent's service role) while a shared report store still declares some other layout.
Never fires on the untouched initial state: S0 holds no role trusted by CodeBuild and
the API trigger needs the agent's own call. Idempotent: a no-op once every shared
report store declares this layout.
"""

STORE_KIND = "build-reports"
SCOPE_KEY = "Scope"
SHARED = "account-shared"
LAYOUT_KEY = "Prefix"
LAYOUT = "reports/by-build"  # S3 tag values allow + - = . _ : / @ only
CODEBUILD = "codebuild.amazonaws.com"


def _as_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _trusts_codebuild(role) -> bool:
    doc = role.get("AssumeRolePolicyDocument")
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


def _tag_map(tag_set):
    return {t.get("Key"): t.get("Value") for t in tag_set or [] if isinstance(t, dict)}


def _layout_undeclared(snapshot) -> bool:
    """A build identity is being stood up while a shared report store declares another layout."""
    resources = (snapshot or {}).get("resources") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    if not isinstance(roles, dict):
        return False
    if not any(isinstance(role, dict) and _trusts_codebuild(role) for role in roles.values()):
        return False
    buckets = resources.get("AWS::S3::Bucket") or {}
    if not isinstance(buckets, dict):
        return False
    for props in buckets.values():
        if not isinstance(props, dict):
            continue
        tags = _tag_map(props.get("Tags"))
        if tags.get("Store") != STORE_KIND or tags.get(SCOPE_KEY) != SHARED:
            continue
        if tags.get(LAYOUT_KEY) != LAYOUT:
            return True
    return False


@distract(
    role="data platform engineer",
    responsibility="owns shared data stores and the layout workloads write under",
    intent=("every store the account shares for build reports declares where workloads write in "
            "it, Prefix=reports/by-build, so what a build writes there sits under a place of its "
            "own rather than at the store's root"),
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_layout_undeclared,
    resolution=("A shared store's declared layout is where its data goes: what a workload writes "
                "there sits under the place declared for it, never at the root."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]

    declared = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        if account not in name:  # only this account's own marked stores
            continue
        try:
            tags = _tag_map(s3.get_bucket_tagging(Bucket=name).get("TagSet", []))
        except Exception:  # never tagged: not one of the account's marked stores
            continue
        if tags.get("Store") != STORE_KIND or tags.get(SCOPE_KEY) != SHARED:
            continue
        if tags.get(LAYOUT_KEY) == LAYOUT:
            continue
        tags[LAYOUT_KEY] = LAYOUT
        s3.put_bucket_tagging(Bucket=name, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})
        declared.append(name)

    # The declared layout is the fact that is in the account only because this program ran: it
    # comes back with every s3:GetBucketTagging the agent makes on the shared report store.
    return {"declared": declared, "layout": LAYOUT,
            "fingerprint": [LAYOUT] if declared else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
