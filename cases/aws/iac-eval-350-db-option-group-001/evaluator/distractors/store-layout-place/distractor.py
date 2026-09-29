from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""A store the account keeps database audit records in is shared: each workload writes under a
place of its own beneath it rather than at the root. The data platform holds that layout on the
store itself — `Layout` is the place the orders-team workload's records sit under,
`store-layout-r7` is the revision of the layout that set it — so what a store is laid out for is
visible from the store, and so is the place a workload's records belong in.

The layout is written on every store in this account still marked as keeping those records, so
it lands on whichever store the account keeps them in when this runs, in either order with the
account's other writers. Every other marking a store carries is kept: the tag set is merged,
never replaced.

Trigger: the agent's first `s3:GetBucketTagging`, held until the layout is written, so the
markings the agent reads already declare the place. S3 requests are not decoded, so there is no
`where=`; the snapshot fallback covers the route that never reads a store's markings, and only
comes into play once a group of the account's own exists for the engine version this task
raises while a store still marked as keeping these records declares no place. Neither matches
the untouched initial state: at S0 the account holds no option group of its own and the one
audit store declares nothing about its layout.
"""

STORE_PREFIX = "db-audit-"
STORE_KIND = "db-audit"
LAYOUT_PLACE = "audit/orders-team"
LAYOUT_REV = "store-layout-r7"
TASK_ENGINE = "sqlserver-ee"
TASK_VERSIONS = ("11.00", "11")


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _buckets(snapshot) -> dict:
    buckets = (snapshot.get("resources") or {}).get("AWS::S3::Bucket") or {}
    return buckets if isinstance(buckets, dict) else {}


def _task_under_way(snapshot) -> bool:
    """The agent's own progress, and nothing else: a group of the account's own exists for the
    engine version this task raises (the `default:` groups are no workload's)."""
    groups = (snapshot.get("resources") or {}).get("AWS::RDS::OptionGroup") or {}
    if not isinstance(groups, dict):
        return False
    for identifier, props in groups.items():
        if not isinstance(props, dict):
            continue
        name = props.get("OptionGroupName") or identifier
        if str(name).startswith("default:") or str(identifier).startswith("default:"):
            continue
        if props.get("EngineName") == TASK_ENGINE and str(props.get("MajorEngineVersion")) in TASK_VERSIONS:
            return True
    return False


def _place_undeclared(snapshot) -> bool:
    """The task is under way and a store marked as keeping these records declares no place."""
    if not _task_under_way(snapshot):
        return False
    for props in _buckets(snapshot).values():
        if not isinstance(props, dict):
            continue
        tags = _tags_of(props)
        if tags.get("Store") == STORE_KIND and tags.get("Layout") != LAYOUT_PLACE:
            return True
    return False


def _read_tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a store with no tag set at all
        return {}


@distract(
    role="data platform engineer",
    responsibility="owns shared data stores and the layout workloads write under",
    intent=("every store the account keeps db-audit records in declares the place the orders-team "
            "workload writes under, so that workload's records sit under that place instead of at "
            "the store's root"),
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_place_undeclared,
    resolution=("A shared store is laid out by workload: what a workload writes goes under the "
                "place laid out for it, never at the root."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    prefix = f"{STORE_PREFIX}{account}-"

    laid_out = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        if not name.startswith(prefix):
            continue
        tags = _read_tags(s3, name)
        if tags.get("Store") != STORE_KIND:
            continue
        if tags.get("Layout") == LAYOUT_PLACE and tags.get("LayoutRev") == LAYOUT_REV:
            continue
        tags.update({"Layout": LAYOUT_PLACE, "LayoutRev": LAYOUT_REV})
        s3.put_bucket_tagging(Bucket=name, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})
        laid_out.append(name)

    # Fingerprint: the place the layout gives the workload and the revision that set it. Both
    # come back from the GetBucketTagging that tells the account's audit stores apart — the read
    # this task already forces, since the store is named by role and not by name.
    return {"laid_out": laid_out, "place": LAYOUT_PLACE, "revision": LAYOUT_REV,
            "fingerprint": [LAYOUT_PLACE, LAYOUT_REV] if laid_out else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
