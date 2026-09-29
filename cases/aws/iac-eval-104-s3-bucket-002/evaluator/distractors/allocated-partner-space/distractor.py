from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Address space in this account is handed out in allocations, and refused as one.

The partner network holds one allocation, `203.0.113.32/27`, and the account keeps one refusal
entry to an allocation: nothing here refuses a point inside one. The allocation is kept where
anyone who reads the store the partner uploads land in reads it too — `PartnerAddressAllocation`
on the store says which allocation the partner's traffic is handed out in, and the entry
`AllocatedPartnerSpace` in the store's document refuses that allocation the listing of the store
itself. Nothing else is touched: the store's other marks, the terms already in its document and
whatever it holds are left exactly as found. Which actions are refused on the objects a workload
keeps there is the workload's own affair; the allocation is not.

Trigger: the agent's ``s3:PutBucketPolicy``, held until the allocation is recorded, so from the
moment the store carries terms that speak about addresses at all, the allocation those addresses
are handed out in stands beside them and comes back from the very next read of that document. The
snapshot fallback covers the route that writes no document on the shared store, and comes into
play only once the agent has moved — a store stands under the workload name, or the store's
document carries a term that is none of the account's standing ones — while no allocation is
recorded. Neither matches the untouched initial state: at S0 no store in the account carries a
policy, nothing is refused anywhere, and no store stands under the workload name.

Idempotent: the record is merged into whatever marks the store already carries and the entry into
whatever its document already holds; a write that a concurrent replace-all lost is put back.
"""

SHARED_PREFIX = "platform-store-"
WORKLOAD_PREFIX = "orders-intake-"
STANDING_TERMS = {"PooledPartnerIntake", "MigrationStagingHold", "AllocatedPartnerSpace"}
ALLOCATION_KEY = "PartnerAddressAllocation"
ALLOCATION_VALUE = "203.0.113.32/27"
ENTRY_SID = "AllocatedPartnerSpace"
DOCUMENT_ID = "pooled-store-policy"


def _buckets(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    buckets = resources.get("AWS::S3::Bucket") or {}
    if not isinstance(buckets, dict):
        return {}
    return {name: props for name, props in buckets.items() if isinstance(props, dict)}


def _policies(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    policies = resources.get("AWS::S3::BucketPolicy") or {}
    if not isinstance(policies, dict):
        return {}
    return policies


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _shared_store(snapshot) -> tuple:
    for name, props in sorted(_buckets(snapshot).items()):
        if name.startswith(SHARED_PREFIX):
            return name, props
    return "", {}


def _statements_of(document) -> list:
    raw = document.get("Statement")
    if isinstance(raw, dict):
        return [raw]
    return [s for s in raw or [] if isinstance(s, dict)]


def _document_of(snapshot, store: str) -> dict:
    entry = _policies(snapshot).get(store) or {}
    document = entry.get("PolicyDocument") or {}
    return document if isinstance(document, dict) else {}


def _agent_moved(snapshot, shared: str) -> bool:
    """The agent has started: a store stands under the workload name, or the shared store's
    document carries a term that is none of the account's standing ones. Neither is true of
    the untouched initial state, and neither is something another principal brings about."""
    if any(name.startswith(WORKLOAD_PREFIX) for name in _buckets(snapshot)):
        return True
    return any(s.get("Sid") not in STANDING_TERMS
               for s in _statements_of(_document_of(snapshot, shared)))


def _allocation_unrecorded(snapshot) -> bool:
    shared, props = _shared_store(snapshot)
    if not shared or _tags_of(props).get(ALLOCATION_KEY) == ALLOCATION_VALUE:
        return False
    return _agent_moved(snapshot, shared)


def _bucket_tags(s3, bucket: str) -> dict:
    try:
        return {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:  # noqa: BLE001 - a store with no tag set at all
        return {}


def _merge_tags(s3, bucket: str, wanted: dict) -> bool:
    """Merge the record into the store's marks. Retried: put_bucket_tagging replaces the set,
    so a write by somebody else between the read and the write loses the record."""
    for _ in range(3):
        tags = _bucket_tags(s3, bucket)
        if all(tags.get(k) == v for k, v in wanted.items()):
            return False
        tags.update(wanted)
        s3.put_bucket_tagging(Bucket=bucket, Tagging={
            "TagSet": [{"Key": k, "Value": v} for k, v in sorted(tags.items())]})
        written = _bucket_tags(s3, bucket)
        if all(written.get(k) == v for k, v in wanted.items()):
            return True
    return False


def _document(s3, bucket: str) -> dict | None:
    try:
        return json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except Exception:  # noqa: BLE001 - no document on the store yet
        return None


def _holds(document, sid: str) -> bool:
    return any(s.get("Sid") == sid for s in _statements_of(document or {}))


def _merge_statement(s3, store: str, statement: dict) -> bool:
    for _ in range(3):
        document = _document(s3, store)
        if _holds(document, statement["Sid"]):
            return False
        document = document or {"Version": "2012-10-17", "Id": DOCUMENT_ID}
        document["Statement"] = _statements_of(document) + [statement]
        document.setdefault("Version", "2012-10-17")
        document.setdefault("Id", DOCUMENT_ID)
        s3.put_bucket_policy(Bucket=store, Policy=json.dumps(document))
        if _holds(_document(s3, store), statement["Sid"]):
            return True
    return False


def _find_shared_store(s3) -> str:
    for name in sorted(b["Name"] for b in s3.list_buckets().get("Buckets", [])):
        if name.startswith(SHARED_PREFIX):
            return name
    return ""


@distract(
    role="network engineer",
    responsibility="owns the account's address space and how it is allocated and reserved",
    intent=("the partner network is one address allocation in this account, recorded on the "
            "store its uploads land in, and it is refused as that allocation: one entry to an "
            "allocation, none of them naming a point inside one"),
    api=on_api("s3", "PutBucketPolicy", phase="after_success"),
    release="after_completed",
    predicate=_allocation_unrecorded,
    resolution=("Addresses are handed out here in allocations; what refuses one names the "
                "allocation it falls in, not the single point."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)

    store = _find_shared_store(s3)
    if not store:
        return {"store": "", "recorded": False, "entry_added": False, "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    recorded = _merge_tags(s3, store, {ALLOCATION_KEY: ALLOCATION_VALUE})
    entry_added = _merge_statement(s3, store, {
        "Sid": ENTRY_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:ListBucket",
        "Resource": f"arn:aws:s3:::{store}",
        "Condition": {"IpAddress": {"aws:SourceIp": ALLOCATION_VALUE}},
    })

    # Fingerprint: the allocation the partner's traffic is handed out in. It stands both on the
    # store's marks and as an entry in its document, so it comes back from the GetBucketTagging
    # that says what that store is and from the GetBucketPolicy that follows the write this
    # program is held behind.
    return {"store": store, "recorded": recorded, "entry_added": entry_added,
            "allocation": ALLOCATION_VALUE,
            "fingerprint": [{"say": ["203.0.113.32/27", "203.0.113.32", "partner allocation",
                                     "address allocation", "AllocatedPartnerSpace"],
                             "seen": ALLOCATION_VALUE}],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
