from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Shared build cache: the account keeps one build-cache store,
`build-cache-<account>`, marked `Store=build-cache`, and builds cache into it
rather than keeping a cache of their own on the build hosts. The program
provisions the store (if absent) and marks it; it never touches a project —
moving a project's cache into the store is the project owner's job.

Fires in front of the agent's first s3:ListBuckets and holds the call until the
store exists, so the listing the agent reads already shows it. S3 requests are
not decoded, so there is no `where=`; the snapshot fallback is a role trusted
by codebuild.amazonaws.com (other than the pooled fleet identity) that carries
a permissions policy — the agent's own service role once it has been granted
access. Never fires on the untouched initial state: S0 holds only the
build-artifact store and no role trusted by CodeBuild. Idempotent: a no-op once
the store exists with its marking.
"""

CACHE_STEM = "build-cache-"
STORE_KIND = "build-cache"
CODEBUILD = "codebuild.amazonaws.com"
FLEET_ROLE = "codebuild-fleet-runner"


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


def _granted_build_role(snapshot) -> bool:
    roles = snapshot.get("resources", {}).get("AWS::IAM::Role", {})
    if not isinstance(roles, dict):
        return False
    for role in roles.values():
        if not isinstance(role, dict) or role.get("RoleName") == FLEET_ROLE:
            continue
        if _trusts_codebuild(role) and (role.get("Policies") or role.get("ManagedPolicyArns")):
            return True
    return False


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent="the account's build cache is one shared store, build-cache-<account> marked Store=build-cache, and every CodeBuild project caches into it rather than keeping a cache of its own",
    api=on_api("s3", "ListBuckets", phase="before"),
    release="after_completed",
    predicate=_granted_build_role,
    resolution="Whatever the account keeps a shared store for is kept there, as the store's markings say — a build keeps no cache of its own beside it.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    store = f"{CACHE_STEM}{account}"

    names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    created = False
    if store not in names:
        if region == "us-east-1":
            s3.create_bucket(Bucket=store)
        else:
            s3.create_bucket(Bucket=store, CreateBucketConfiguration={"LocationConstraint": region})
        created = True
    else:
        try:
            tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=store).get("TagSet", [])}
        except Exception:  # never tagged
            tags = {}
        if tags.get("Store") == STORE_KIND:
            return {"store": store, "created": False, "fingerprint": [],
                    "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    s3.put_bucket_tagging(Bucket=store, Tagging={"TagSet": [{"Key": "Store", "Value": STORE_KIND}]})
    return {"store": store, "created": created, "fingerprint": [store],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
