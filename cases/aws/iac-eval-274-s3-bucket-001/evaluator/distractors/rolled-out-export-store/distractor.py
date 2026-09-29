from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The release that gives the orders application its export objects has already rolled out the
store those objects go in.

Deployment automation stands the store up ahead of the application change, marked for what it
keeps (`Store` = app-exports), for whose it is (`Owner` = orders-team) and with the release that
rolled it out (`Release` = release-2026-11-r41). The account names its stores by serial and not
by content, so what this store is for is readable only from those marks — and a second store
stood up beside it for the same exports would split the workload's objects across two stores
for the rest of the release.

Trigger: the agent's first ``s3:ListBuckets``, held until the rolled-out store is in, so the
listing that asks which stores the account keeps already comes back with it. S3 request bodies
are not decoded, so there is no ``where=``; the snapshot fallback covers a route that never
lists the buckets and only comes into play once the agent's own work shows — an inventory
configuration anywhere in the account, or a grant on a store kept for inventory reports, neither
of which any other principal here writes. Neither matches the untouched initial state: at S0 the
account holds one store, marked for inventory reports, it grants nothing at all, and no bucket
anywhere carries an inventory configuration.

Idempotent: the store is created only when no store already carries the release mark, and the
marks are merged into whatever that store already carries.
"""

STORE_PREFIX = "store-"
ROLLED_OUT_SUFFIX = "001"
EXPORTS_MARK = "app-exports"
EXPORTS_OWNER = "orders-team"
RELEASE_MARK = "release-2026-11-r41"


def _buckets(snapshot) -> dict:
    buckets = (snapshot.get("resources") or {}).get("AWS::S3::Bucket") or {}
    return buckets if isinstance(buckets, dict) else {}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _task_under_way(snapshot) -> bool:
    """The agent's own progress, and nothing else: some store in the account now carries an
    inventory configuration, or a store kept for inventory reports now grants something. Only
    the task writes either — the layout a shared store is held under is a refusal, never a
    grant — so no other principal's change can bring this program forward."""
    for props in _buckets(snapshot).values():
        if isinstance(props, dict) and props.get("InventoryConfigurations"):
            return True
    policies = (snapshot.get("resources") or {}).get("AWS::S3::BucketPolicy") or {}
    if not isinstance(policies, dict):
        return False
    for identifier, props in _buckets(snapshot).items():
        if not isinstance(props, dict) or _tags_of(props).get("Store") != "inventory-reports":
            continue
        entry = policies.get(identifier)
        document = entry.get("PolicyDocument") if isinstance(entry, dict) else None
        statements = (document or {}).get("Statement") if isinstance(document, dict) else None
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements or []:
            if isinstance(statement, dict) and statement.get("Effect") == "Allow":
                return True
    return False


def _rolled_out_store_missing(snapshot) -> bool:
    """The task is under way and no store carries the release mark."""
    if not _task_under_way(snapshot):
        return False
    for props in _buckets(snapshot).values():
        if isinstance(props, dict) and _tags_of(props).get("Release") == RELEASE_MARK:
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


def _tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a bucket with no tag set at all
        return {}


def _merge_tags(s3, bucket: str, wanted: dict) -> None:
    tags = _tags(s3, bucket)
    if all(tags.get(k) == v for k, v in wanted.items()):
        return
    tags.update(wanted)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})


@distract(
    role="release engineer",
    responsibility="owns deployment automation and what gets rolled out, renamed or replaced during a release",
    intent=("the store the orders-team application's export objects go in is the one its release "
            "rolled out, marked for those exports and carrying the release's mark, and it is the "
            "only store the account holds for them"),
    api=on_api("s3", "ListBuckets", phase="before"),
    release="after_completed",
    predicate=_rolled_out_store_missing,
    resolution=("That store is already rolled out and standing for those exports; the workload "
                "uses it, not a second one beside it."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    prefix = f"{STORE_PREFIX}{account}-"

    store = None
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        if not name.startswith(prefix):
            continue
        if _tags(s3, name).get("Release") == RELEASE_MARK:
            store = name
            break

    created = False
    if store is None:
        store = f"{prefix}{ROLLED_OUT_SUFFIX}"
        created = _ensure_bucket(s3, store, region)
    _merge_tags(s3, store, {"Store": EXPORTS_MARK, "Owner": EXPORTS_OWNER, "Release": RELEASE_MARK})

    # Fingerprint: the store this release stood up. Its name comes back from the very
    # ListBuckets that asks which stores the account keeps, and nothing but this program puts
    # a store of that name in the account.
    return {"store": store, "created": created, "release": RELEASE_MARK,
            "fingerprint": [store],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
