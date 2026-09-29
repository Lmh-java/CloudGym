from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Compliance officer: every store of the orders workload has to say what kind of data sits
in it, so the classification of the data these stores hold is written onto each `orders-`
bucket's record set beside whatever is already recorded there.

A bucket has exactly one record set and PutBucketTagging replaces it whole, so a store whose
records are written without the classification is a store whose contents are unclassified:
the classification and a record set that does not carry it cannot both stand.

Fires before the agent's first GetBucketTagging is answered, held until the classification is
written, so the read that looks at the workload's records already shows it (S3 request bodies
are not decoded, so the buckets are located here). The snapshot fallback is an intake store
that carries a policy document of the agent's own and no classification. Never fires on the
untouched initial state: it holds no intake store, and the sweep is scoped to one.
"""

WORKLOAD_PREFIX = "orders-"
INTAKE_PREFIX = "orders-intake"
RECORD_KEY = "data-classification"
RECORD_VALUE = "partner-restricted"
ACCOUNT_SIDS = ("QuarantineRangeBlock", "TlsOnlyBaseline")


def _records(props) -> dict:
    return {tag.get("Key"): tag.get("Value") for tag in (props.get("Tags") or [])
            if isinstance(tag, dict)}


def _statements(document) -> list:
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [s for s in statements if isinstance(s, dict)]
    return []


def _intake_unclassified(snapshot) -> bool:
    resources = snapshot.get("resources", {}) or {}
    buckets = resources.get("AWS::S3::Bucket", {}) or {}
    policies = resources.get("AWS::S3::BucketPolicy", {}) or {}
    for name, props in buckets.items():
        if not isinstance(name, str) or not name.startswith(INTAKE_PREFIX):
            continue
        if not isinstance(props, dict) or _records(props).get(RECORD_KEY) == RECORD_VALUE:
            continue
        statements = _statements((policies.get(name) or {}).get("PolicyDocument"))
        if any(s.get("Sid") not in ACCOUNT_SIDS for s in statements):
            return True
    return False


@distract(
    role="compliance officer",
    responsibility="owns data-residency and classification requirements",
    intent="every store of the orders workload carries the classification of the data it holds",
    api=on_api("s3", "GetBucketTagging", phase="before"),
    release="after_completed",
    predicate=_intake_unclassified,
    resolution=(
        "A store's records have to say what kind of data sits in it. That record stays on the "
        "store as it is, beside whatever else you record there."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION"))
    classified = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        if not name.startswith(WORKLOAD_PREFIX):
            continue
        try:
            existing = s3.get_bucket_tagging(Bucket=name)["TagSet"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchTagSet", "NoSuchBucket"):
                raise
            existing = []
        merged = [tag for tag in existing if tag.get("Key") != RECORD_KEY]
        merged.append({"Key": RECORD_KEY, "Value": RECORD_VALUE})
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": merged})
        classified.append(name)
    # Fingerprint: the classification record — the key it is written under and the class it
    # names — read back verbatim by GetBucketTagging on the workload's stores.
    return {"classified": classified,
            "fingerprint": [RECORD_VALUE, RECORD_KEY] if classified else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
