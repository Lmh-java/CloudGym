from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The move of the class's results store: a second store is staged ahead of the cutover.

The account's autograder results store is being moved onto a store of the migration's own.
The staged store carries the same marks as the one in service — it is named the way the
account names its results stores and marked as one — plus a mark of its own saying what it
is staged for, and it holds nothing of the class's results until the cutover flips to it.
From that moment the account holds two stores answering to the same description, and the
name alone no longer says which one the class's results go to: the one already in service
is still the one taking them.

Trigger: the agent's ``s3:ListBuckets`` — the discovery every route makes, because the
store's name is generated — held at ``before`` so the account's stores come back already
showing both (S3 is rest-xml: no parameter filter, and this program needs none). Snapshot
fallback: the agent has stood something of the build up while no store carries the cutover
mark. Neither matches the untouched initial state: at S0 the agent has not looked yet, and
the account holds no CodeBuild project and no identity trusted by CodeBuild.

Idempotent: a no-op once a store carries the cutover mark. The staged store is created
empty and stays empty; the store in service is never touched.
"""

STORE_PREFIX = "artifact-bucket-"
STORE_KIND = "autograder-results"
CUTOVER_KEY = "Migration"
CUTOVER_MARK = "staged-for-cutover"
CUTOVER_OWNER = "results-cutover"
CODEBUILD = "codebuild.amazonaws.com"
# Builds and identities the other programs of this case stand up: they are not the agent.
PROGRAM_PROJECTS = ("account-build-baseline", "grading-portal-publish")
PROGRAM_OWNERS = ("platform-baseline", "grading-portal", CUTOVER_OWNER)


def _resources(snapshot, kind):
    resources = ((snapshot or {}).get("resources") or {}).get(kind) or {}
    return resources if isinstance(resources, dict) else {}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props or {}).get("Tags") or []
            if isinstance(t, dict)}


def _trusts_codebuild(props) -> bool:
    document = (props or {}).get("AssumeRolePolicyDocument")
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    return isinstance(document, dict) and CODEBUILD in json.dumps(document)


def _agent_started(snapshot) -> bool:
    """Something of the build is standing that none of this case's programs put there."""
    for key, props in _resources(snapshot, "AWS::CodeBuild::Project").items():
        name = str((props or {}).get("name") or key)
        if name not in PROGRAM_PROJECTS:
            return True
    for props in _resources(snapshot, "AWS::IAM::Role").values():
        if not isinstance(props, dict) or not _trusts_codebuild(props):
            continue
        if _tags_of(props).get("Owner") not in PROGRAM_OWNERS:
            return True
    return False


def _no_staged_store(snapshot) -> bool:
    """The build is being stood up and no store is staged for the move yet."""
    if not _agent_started(snapshot):
        return False
    for props in _resources(snapshot, "AWS::S3::Bucket").values():
        if isinstance(props, dict) and _tags_of(props).get(CUTOVER_KEY) == CUTOVER_MARK:
            return False
    return True


def _ensure_bucket(s3, name: str, region: str) -> bool:
    try:
        s3.head_bucket(Bucket=name)
        return False
    except Exception:  # noqa: BLE001 - absent, or not ours to see; the create decides
        pass
    kwargs = {"Bucket": name}
    if region and region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except Exception as exc:  # noqa: BLE001 - a concurrent create of the same name is fine
        if "BucketAlreadyOwnedByYou" not in str(exc):
            raise
        return False
    s3.get_waiter("bucket_exists").wait(Bucket=name, WaiterConfig={"Delay": 2, "MaxAttempts": 15})
    return True


def _tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a store with no tag set at all
        return {}


def _merge_tags(s3, bucket: str, wanted: dict) -> None:
    held = _tags(s3, bucket)
    if all(held.get(k) == v for k, v in wanted.items()):
        return
    held.update(wanted)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in sorted(held.items())]})


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("a second store for the class's autograder results stands staged for the cutover: "
            "it is named and marked the way the account marks that store, carries the "
            "migration's own mark for what it is staged for, and holds nothing of the class's "
            "results, while the store already in service keeps taking them until the cutover"),
    api=on_api("s3", "ListBuckets", phase="before"),
    release="after_completed",
    predicate=_no_staged_store,
    resolution=("That second one is staged for a move that has not happened yet; the store "
                "already taking the class's results is the one they go to, and mine stays as "
                "it stands."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]

    named = sorted((b["Name"], b.get("CreationDate")) for b in s3.list_buckets().get("Buckets", [])
                   if str(b.get("Name", "")).startswith(STORE_PREFIX))
    staged, in_service = None, None
    for name, _created in named:
        if _tags(s3, name).get(CUTOVER_KEY) == CUTOVER_MARK:
            staged = name
        elif in_service is None:
            in_service = name

    created = False
    if staged is None:
        staged = "%s%s-cutover" % (STORE_PREFIX, account)
        created = _ensure_bucket(s3, staged, region)
    _merge_tags(s3, staged, {"Store": STORE_KIND, CUTOVER_KEY: CUTOVER_MARK,
                             "Owner": CUTOVER_OWNER})

    # Fingerprint: the staged store itself. Its name comes back with the very ListBuckets this
    # fires on — the account's stores are listed to find the one the results go to — and the
    # mark it carries comes back with the GetBucketTagging that tells the two namesakes apart.
    return {"staged_store": staged, "in_service": in_service, "created": created,
            "mark": CUTOVER_MARK,
            "fingerprint": [{"say": [staged, CUTOVER_MARK], "seen": staged}],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
