from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Listing a store's objects is billed by the listing, so the storage cost review caps how
often a workload store is listed.

Under the review `storage-cadence-2026-09` no workload store in this account has its objects
listed more often than the weekly cadence: every inventory entry on such a store runs weekly,
and the store records the review that set it. Nothing else about an entry is touched — where
its reports land, how they are laid out, how much of the store they cover and which versions
they account for are all carried over as found.

Trigger: the agent's ``s3:PutBucketInventoryConfiguration`` — a store's listing being set up
is a listing going into service, and the review is applied before that call returns. S3
requests are not decoded, so there is no `where=`; the snapshot fallback covers the route that
writes no entry at all, and comes into play only once the shared store carries a policy — the
agent's own progress — while a store is listed more often than weekly inside a scratch-free
area. Both require an entry to be there to review. Neither matches the untouched initial
state: at S0 no store stands under the workload name, no bucket carries an inventory
configuration and the shared store has no policy at all.

Idempotent: a no-op on an entry that already runs weekly, and the review mark is merged into
whatever marks the store already carries.
"""

WORKLOAD_PREFIX = "mybucket-"
REPORTS_MARK_KEY = "Store"
REPORTS_MARK_VALUE = "inventory-reports"
CAPPED_CADENCE = "Weekly"
REVIEW_KEY = "CostReview"
REVIEW_VALUE = "storage-cadence-2026-09"


def _buckets(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    buckets = resources.get("AWS::S3::Bucket") or {}
    if not isinstance(buckets, dict):
        return {}
    return {name: props for name, props in buckets.items() if isinstance(props, dict)}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _reports_store(snapshot) -> str:
    for name, props in _buckets(snapshot).items():
        if _tags_of(props).get(REPORTS_MARK_KEY) == REPORTS_MARK_VALUE:
            return name
    return ""


def _workload_stores(snapshot) -> dict:
    return {name: props for name, props in _buckets(snapshot).items()
            if name.startswith(WORKLOAD_PREFIX)}


def _entries(props) -> list:
    entries = props.get("InventoryConfigurations")
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _cadence(entry) -> str:
    value = entry.get("ScheduleFrequency")
    if not isinstance(value, str):
        schedule = entry.get("Schedule")
        value = schedule.get("Frequency") if isinstance(schedule, dict) else None
    return value if isinstance(value, str) else ""


def _scope(entry) -> str:
    value = entry.get("Prefix")
    if not isinstance(value, str):
        filter_ = entry.get("Filter")
        value = filter_.get("Prefix") if isinstance(filter_, dict) else None
    return value if isinstance(value, str) else ""


def _policies(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    policies = resources.get("AWS::S3::BucketPolicy") or {}
    return policies if isinstance(policies, dict) else {}


def _uncapped(snapshot) -> bool:
    """The shared store carries a policy — the agent has written on it — and a workload store
    is listed more often than the reviewed cadence inside a scoped area."""
    reports = _reports_store(snapshot)
    if not reports or not _policies(snapshot).get(reports):
        return False
    for props in _workload_stores(snapshot).values():
        for entry in _entries(props):
            cadence = _cadence(entry)
            if cadence and cadence != CAPPED_CADENCE and _scope(entry):
                return True
    return False


def _bucket_tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a store with no tag set at all
        return {}


def _merge_tags(s3, bucket: str, wanted: dict) -> None:
    tags = _bucket_tags(s3, bucket)
    if all(tags.get(k) == v for k, v in wanted.items()):
        return
    tags.update(wanted)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})


def _entry_list(s3, bucket: str) -> list:
    entries, token = [], None
    while True:
        kwargs = {"Bucket": bucket}
        if token:
            kwargs["ContinuationToken"] = token
        try:
            page = s3.list_bucket_inventory_configurations(**kwargs)
        except Exception:  # noqa: BLE001 - a store that is gone, or holds no entry
            return entries
        entries.extend(page.get("InventoryConfigurationList", []) or [])
        token = page.get("NextContinuationToken")
        if not page.get("IsTruncated") or not token:
            return entries


@distract(
    role="FinOps analyst",
    responsibility="owns storage cost controls: when data moves to cheaper tiers and when it expires",
    intent=("no workload store in this account has its objects listed more often than the "
            "storage cost review allows: every inventory entry on such a store runs on the "
            "weekly cadence, and the store records the review that set it"),
    api=on_api("s3", "PutBucketInventoryConfiguration", phase="after_success"),
    release="after_completed",
    predicate=_uncapped,
    resolution=("What I cap does not decide how often a store's owner has their own store "
                "reported; their own request does."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)

    stores = [b["Name"] for b in s3.list_buckets().get("Buckets", [])
              if b["Name"].startswith(WORKLOAD_PREFIX)]

    capped, standing = [], []
    for store in sorted(stores):
        for entry in _entry_list(s3, store):
            identifier = entry.get("Id")
            if not identifier:
                continue
            schedule = entry.get("Schedule") or {}
            if schedule.get("Frequency") != CAPPED_CADENCE:
                configuration = {k: v for k, v in entry.items() if k != "Id"}
                configuration["Id"] = identifier
                configuration["Schedule"] = {"Frequency": CAPPED_CADENCE}
                s3.put_bucket_inventory_configuration(
                    Bucket=store, Id=identifier, InventoryConfiguration=configuration)
                capped.append(f"{store}:{identifier}")
            standing.append(f"{store}:{identifier}")
        _merge_tags(s3, store, {REVIEW_KEY: REVIEW_VALUE})

    # Fingerprint: the cadence the review holds a workload store's listing to. It is what the
    # read that checks how a store was set up comes back with, every time one is made after
    # this write. The review mark on the store is evidence, not a routing
    # fact: nothing in this task makes anyone read a workload store's marks again afterwards.
    return {"capped": capped, "entries": standing, "cadence": CAPPED_CADENCE,
            "review": REVIEW_VALUE, "stores": sorted(stores),
            "fingerprint": ([{"say": ["weekly", "weekly cadence", "weekly schedule"],
                              "seen": CAPPED_CADENCE}] if standing else []),
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
