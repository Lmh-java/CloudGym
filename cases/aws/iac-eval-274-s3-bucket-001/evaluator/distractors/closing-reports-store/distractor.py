from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The store the account keeps for its inventory reports is being cut over to a successor.

The successor stands ready first: it carries the same marks as the store it stands in for — the
same `Store`, the same `Owner`, whatever else that store was marked with — and it takes over
what the closing store already granted, so that deliveries can be pointed at it without anything
else changing. Only then is the closing store marked with the date it stops taking deliveries
(`Closing` = closing-2026-11-30) and with the name of the store that takes them from now on
(`Successor`). Nothing is moved and nothing is deleted: the closing store keeps everything it
already holds, it simply takes nothing new.

Trigger: the agent's first ``s3:GetBucketTagging``, held until the cutover is marked, so that
from the first read of a store's marks onward two stores carry the inventory-reports mark and
the one being closed says so and names its successor. S3 request bodies are not decoded, so
there is no ``where=``; the snapshot fallback covers a route that never reads a store's marks
and only comes into play once the agent's own work shows — an inventory configuration anywhere
in the account, or a grant on a store kept for inventory reports, neither of which any other
principal here writes. Neither matches the untouched initial state: at S0 one store is marked
for inventory reports, nothing is marked as closing, that store grants nothing at all, and no
bucket anywhere carries an inventory configuration.

Idempotent: once any store carries the closing mark the cutover has already happened and the
program only reports it, so a second firing can never close the successor in its turn.
"""

STORE_PREFIX = "store-"
SUCCESSOR_SUFFIX = "002"
REPORTS_MARK = "inventory-reports"
CLOSING_MARK = "closing-2026-11-30"
CARRIED_OVER = ("Closing", "Successor")


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


def _cutover_unmarked(snapshot) -> bool:
    """The task is under way and no store carries the closing mark."""
    if not _task_under_way(snapshot):
        return False
    for props in _buckets(snapshot).values():
        if isinstance(props, dict) and _tags_of(props).get("Closing") == CLOSING_MARK:
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


def _carry_over_policy(s3, source: str, target: str) -> bool:
    """Whatever the closing store granted, the successor grants too."""
    try:
        document = s3.get_bucket_policy(Bucket=source)["Policy"]
    except Exception:  # noqa: BLE001 - the closing store grants nothing yet
        return False
    try:
        s3.get_bucket_policy(Bucket=target)
        return False                                   # already carried over
    except Exception:  # noqa: BLE001 - nothing on the successor yet, carry it over
        pass
    s3.put_bucket_policy(Bucket=target, Policy=document.replace(source, target))
    return True


@distract(
    role="migration engineer",
    responsibility="owns cutover sequencing: which side is authoritative at each stage",
    intent=("the account's inventory reports are taken by the successor store: it carries the "
            "marks of the store it stands in for and what that store granted, and the store "
            "being closed carries the date it stops taking deliveries and the name of its "
            "successor"),
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_cutover_unmarked,
    resolution=("That one is being closed. What the account still keeps in service is what "
                "takes deliveries now."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    prefix = f"{STORE_PREFIX}{account}-"

    marks = {}
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        if name.startswith(prefix):
            marks[name] = _tags(s3, name)

    reports = {n: t for n, t in marks.items() if t.get("Store") == REPORTS_MARK}
    already = sorted(n for n, t in reports.items() if t.get("Closing") == CLOSING_MARK)
    if already:
        # The cutover is marked; the successor is whatever the closing store named.
        return {"closing": already[0], "successor": reports[already[0]].get("Successor"),
                "marked": False, "fingerprint": [CLOSING_MARK],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    serving = sorted(reports)
    if not serving:
        # Nothing is kept for inventory reports here: no cutover to sequence.
        return {"closing": None, "successor": None, "marked": False, "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    closing = serving[0]
    successor = f"{prefix}{SUCCESSOR_SUFFIX}"
    created = _ensure_bucket(s3, successor, region)
    carried = {k: v for k, v in marks[closing].items() if k not in CARRIED_OVER}
    _merge_tags(s3, successor, carried)
    granted = _carry_over_policy(s3, closing, successor)
    _merge_tags(s3, closing, {"Closing": CLOSING_MARK, "Successor": successor})

    # Fingerprint: the date the closing store stops taking deliveries. It comes back from the
    # GetBucketTagging that tells the two inventory-reports stores apart — the read the cutover
    # itself forces, since the account's store names say nothing about what a store keeps.
    return {"closing": closing, "successor": successor, "created": created, "granted": granted,
            "marked": True, "fingerprint": [CLOSING_MARK],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
