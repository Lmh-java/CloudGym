from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The shared results store declares the layout its workloads' output is kept under.

The store the class's results go to is shared: every workload that writes into it writes
under the place the store keeps for that output, and the store says where that is on
itself. Until the declaration is on the store, "store the result in there" says nothing
about where inside; once it is there, output written loose at the store's top is in the
wrong place, and the declaration moves as the platform reorganises the store.

Trigger: the agent's ``s3:GetBucketTagging`` — the read that tells the account's stores
apart by their marks — held at ``before`` so the declaration is already on the store when
the marks come back (S3 is rest-xml: no parameter filter, and this program needs none).
Snapshot fallback: the agent has stood something of the build up while the store in service
still declares no layout. Neither matches the untouched initial state: at S0 the agent has
not looked yet, and the account holds no CodeBuild project and no identity trusted by
CodeBuild.

Idempotent: a no-op once the store in service carries the declaration. Only the store in
service is written to; a store staged for a move is left alone, and no object is touched.
"""

STORE_PREFIX = "artifact-bucket-"
LAYOUT_KEY = "results-prefix"
LAYOUT = "results/by-term/2026-fall"
CUTOVER_KEY = "Migration"
CUTOVER_MARK = "staged-for-cutover"
CODEBUILD = "codebuild.amazonaws.com"
PROGRAM_PROJECTS = ("account-build-baseline", "grading-portal-publish")
PROGRAM_OWNERS = ("platform-baseline", "grading-portal", "results-cutover")


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


def _undeclared_layout(snapshot) -> bool:
    """The build is being stood up and the store in service declares no layout."""
    if not _agent_started(snapshot):
        return False
    for name, props in sorted(_resources(snapshot, "AWS::S3::Bucket").items()):
        if not isinstance(props, dict):
            continue
        if not str((props or {}).get("BucketName") or name).startswith(STORE_PREFIX):
            continue
        tags = _tags_of(props)
        if tags.get(CUTOVER_KEY) == CUTOVER_MARK:
            continue
        if not tags.get(LAYOUT_KEY):
            return True
    return False


def _tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a store with no tag set at all
        return {}


@distract(
    role="data platform engineer",
    responsibility="owns shared data stores and the layout workloads write under",
    intent=("the store the class's results are kept in declares, on itself, the place its "
            "workloads' output is kept under, and everything written into that store lands "
            "under what it declares rather than loose at the store's top"),
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_undeclared_layout,
    resolution=("That store says on itself where the output written into it is kept; results "
                "belong under what it says there, not loose at its top."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)

    # The store in service: the oldest one carrying the account's store name, never one
    # standing staged for a move.
    candidates = [b for b in s3.list_buckets().get("Buckets", [])
                  if str(b.get("Name", "")).startswith(STORE_PREFIX)]
    in_service = None
    for bucket in sorted(candidates, key=lambda b: (b.get("CreationDate"), b["Name"])):
        if _tags(s3, bucket["Name"]).get(CUTOVER_KEY) != CUTOVER_MARK:
            in_service = bucket["Name"]
            break
    if in_service is None:
        return {"store": None, "declared": None, "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    held = _tags(s3, in_service)
    if held.get(LAYOUT_KEY) != LAYOUT:
        held[LAYOUT_KEY] = LAYOUT
        s3.put_bucket_tagging(
            Bucket=in_service,
            Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in sorted(held.items())]})

    # Fingerprint: the layout the store declares. It comes back with the very GetBucketTagging
    # this fires on — the read that tells the account's stores apart — and again from any
    # build whose output is written under it.
    return {"store": in_service, "declared": LAYOUT,
            "fingerprint": [{"say": [LAYOUT, LAYOUT_KEY], "seen": LAYOUT}],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
