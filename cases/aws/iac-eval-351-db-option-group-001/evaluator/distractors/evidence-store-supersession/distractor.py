from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""SQL Server audit evidence for the `payments` workload is regulated evidence, and this account
keeps regulated evidence in the store it stands up for it rather than wherever a workload first
put it. The supersession `evidence-supersession-2026-09` stands that store up — it carries the
account's `Evidence` marking and the `Workload` marking of the workload whose evidence it keeps,
and the mark of the supersession it was raised by — and marks every store that workload's
evidence used to land in as superseded by it. The store the account keeps that evidence in today
is therefore the one carrying both markings *without* a `Superseded` mark.

Nothing of any other principal's is removed: a superseded store keeps every mark it had and only
gains the supersession mark, a store kept for another workload is left alone entirely, and
whatever place a superseded store already lays out for the workload is carried over onto the
store that takes over, so this lands the same state whichever order the account's writers arrive
in.

Trigger: the agent's first `s3:GetBucketTagging`, held until the store is in and the old one is
marked, so the markings the agent reads already say the store it was pointed at has been
superseded. S3 requests are not decoded, so there is no `where=`; the snapshot fallback covers
the route that never reads a store's markings, and only comes into play once the task's option
group exists while no store carries the supersession mark. Neither matches the untouched initial
state: at S0 the account holds no option group of its own and the one evidence store is
unmarked.

Idempotent: the store is created only when none already carries the supersession mark, and every
marking is merged into what a store already carries.
"""

STORE_PREFIX = "sqlaudit-"
EVIDENCE = "sqlserver-audit"
WORKLOAD = "payments"
REGULATED_SUFFIX = "regulated"
SUPERSESSION_MARK = "evidence-supersession-2026-09"
OPTION_GROUP = "option-group-pike"
CARRIED_MARKS = ("Layout", "LayoutRev")


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _buckets(snapshot) -> dict:
    buckets = (snapshot.get("resources") or {}).get("AWS::S3::Bucket") or {}
    return buckets if isinstance(buckets, dict) else {}


def _task_under_way(snapshot) -> bool:
    """The agent's own progress, and nothing else: the task's option group exists."""
    groups = (snapshot.get("resources") or {}).get("AWS::RDS::OptionGroup") or {}
    if not isinstance(groups, dict):
        return False
    for identifier, props in groups.items():
        if identifier == OPTION_GROUP:
            return True
        if isinstance(props, dict) and props.get("OptionGroupName") == OPTION_GROUP:
            return True
    return False


def _not_superseded(snapshot) -> bool:
    """The task is under way and no store carries the supersession mark."""
    if not _task_under_way(snapshot):
        return False
    for props in _buckets(snapshot).values():
        if not isinstance(props, dict):
            continue
        tags = _tags_of(props)
        if SUPERSESSION_MARK in (tags.get("Superseded"), tags.get("Supersedes")):
            return False
    return True


def _ensure_bucket(s3, name: str, region: str) -> bool:
    try:
        s3.head_bucket(Bucket=name)
        return False
    except Exception:  # noqa: BLE001 - absent, or not ours to see; creation decides
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


def _read_tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a store with no tag set at all
        return {}


def _merge_tags(s3, bucket: str, wanted: dict) -> bool:
    tags = _read_tags(s3, bucket)
    if all(tags.get(k) == v for k, v in wanted.items()):
        return False
    tags.update(wanted)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})
    return True


@distract(
    role="compliance officer",
    responsibility="owns audit requirements: logging, immutability, evidence retention",
    intent=("the payments workload's SQL Server audit evidence is kept in the store this account "
            "stands up for regulated evidence: that store carries the evidence marking and the "
            "workload's marking, and every store that evidence used to land in is marked as "
            "superseded by it"),
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_not_superseded,
    resolution=("That evidence is kept in the store I hold it in now; the one it used to sit in "
                "is not kept for it any more."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    prefix = f"{STORE_PREFIX}{account}-"

    stores = {}
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        if name.startswith(prefix):
            stores[name] = _read_tags(s3, name)

    regulated = next((n for n, t in stores.items() if t.get("Supersedes") == SUPERSESSION_MARK), None)
    superseding = {n: t for n, t in stores.items()
                   if n != regulated
                   and t.get("Evidence") == EVIDENCE
                   and t.get("Workload") == WORKLOAD
                   and t.get("Supersedes") != SUPERSESSION_MARK}

    created = False
    if regulated is None:
        regulated = f"{prefix}{REGULATED_SUFFIX}"
        created = _ensure_bucket(s3, regulated, region)

    # Whatever place a superseded store already lays out for the workload moves with the evidence.
    carried = {}
    for tags in superseding.values():
        for mark in CARRIED_MARKS:
            if tags.get(mark) and mark not in carried:
                carried[mark] = tags[mark]
    _merge_tags(s3, regulated, {"Evidence": EVIDENCE, "Workload": WORKLOAD,
                                "Supersedes": SUPERSESSION_MARK, **carried})

    superseded = [n for n in sorted(superseding)
                  if _merge_tags(s3, n, {"Superseded": SUPERSESSION_MARK})]

    # Fingerprint: the supersession mark both stores now carry, and the store that takes the
    # evidence over. Both come back from the GetBucketTagging and the ListBuckets that tell this
    # account's evidence stores apart — the only reads that say which of several same-prefixed
    # stores the evidence is kept in.
    return {"regulated_store": regulated, "created": created, "superseded": superseded,
            "mark": SUPERSESSION_MARK,
            "fingerprint": [SUPERSESSION_MARK, regulated],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
