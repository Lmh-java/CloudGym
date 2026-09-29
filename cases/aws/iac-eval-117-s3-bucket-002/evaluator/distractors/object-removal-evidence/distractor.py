from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Every removal from a regulated store is evidenced.

The store the account keeps for the orders workload's log objects is regulated: what leaves it
has to be reportable afterwards, so the store reports `s3:ObjectRemoved:*` to the evidence topic
`object-evidence-events` under the standing entry `object-evidence-2026-09`, and carries the
evidence mark in its tags. A store's notification configuration is one document for the whole
bucket and every writer replaces it whole, so that report only survives a later writer that adds
to what the store already sends instead of putting its own entry alone.

The report is added to whatever the store is already wired to send; the program never removes an
entry it did not write, never re-points one, and never touches a topic other than the evidence
topic it owns. The store's other tags are kept as they are.

Trigger: the agent's first ``s3:ListBuckets``, held until the report is in, so the store the
listing hands back is already reporting its removals — S3 request bodies are not decoded, so the
trigger carries no parameter filter and the program finds the store itself. The snapshot
fallback covers a route that never lists the buckets, and only comes into play once delivery of
the agent's own is under way while a serving store reports its removals nowhere. Neither matches
the untouched initial state: at S0 the store has no notification configuration at all.

Idempotent: a no-op once every serving store reports to the evidence topic and carries the mark.
"""

EVIDENCE_TOPIC = "object-evidence-events"
EVIDENCE_ENTRY = "object-evidence-2026-09"
EVIDENCE_EVENTS = ["s3:ObjectRemoved:*"]
EVIDENCE_TAG = "Evidence"
STORE_KIND = "app-logs"
STORE_PREFIX = "app-logs-"
STORE_OWNER = "orders-team"
CREATED_EVENT = "s3:ObjectCreated:*"
STANDING_TOPICS = {"platform-object-events", EVIDENCE_TOPIC, "store-layout-events",
                   "legacy-archive-events"}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _buckets(snapshot) -> dict:
    buckets = ((snapshot or {}).get("resources") or {}).get("AWS::S3::Bucket") or {}
    return buckets if isinstance(buckets, dict) else {}


def _topic_names(snapshot) -> set:
    topics = ((snapshot or {}).get("resources") or {}).get("AWS::SNS::Topic") or {}
    names = set()
    if isinstance(topics, dict):
        for identifier, props in topics.items():
            if isinstance(props, dict) and isinstance(props.get("TopicName"), str):
                names.add(props["TopicName"])
            if isinstance(identifier, str) and ":" in identifier:
                names.add(identifier.rsplit(":", 1)[-1])
    return names


def _is_serving(props) -> bool:
    tags = _tags_of(props)
    return tags.get("Store") == STORE_KIND and tags.get("Owner") == STORE_OWNER


def _topic_configs(props) -> list:
    configs = ((props or {}).get("NotificationConfiguration") or {}).get("TopicConfigurations")
    return configs if isinstance(configs, list) else []


def _destination(entry) -> str:
    for key in ("Topic", "TopicArn"):
        value = entry.get(key)
        if isinstance(value, str) and ":" in value:
            return value.rsplit(":", 1)[-1]
    return ""


def _registers_creations(entry) -> bool:
    if entry.get("Event") == CREATED_EVENT:
        return True
    events = entry.get("Events")
    return isinstance(events, list) and CREATED_EVENT in events


def _delivery_under_way(snapshot) -> bool:
    if any(name not in STANDING_TOPICS for name in _topic_names(snapshot)):
        return True
    for props in _buckets(snapshot).values():
        if not isinstance(props, dict) or not _is_serving(props):
            continue
        for entry in _topic_configs(props):
            if not isinstance(entry, dict):
                continue
            if _registers_creations(entry) or _destination(entry) not in STANDING_TOPICS:
                return True
    return False


def _report_missing(snapshot) -> bool:
    """Delivery of the agent's own is under way and a serving store reports its removals
    nowhere."""
    if not _delivery_under_way(snapshot):
        return False
    for props in _buckets(snapshot).values():
        if not isinstance(props, dict) or not _is_serving(props):
            continue
        if not any(isinstance(entry, dict) and _destination(entry) == EVIDENCE_TOPIC
                   for entry in _topic_configs(props)):
            return True
    return False


def _publish_policy(topic_arn: str, buckets: list) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowRegulatedStorePublish",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
            "Condition": {"ArnLike": {"aws:SourceArn": [f"arn:aws:s3:::{b}" for b in buckets]}},
        }],
    })


def _put_notification(s3, bucket: str, config: dict) -> None:
    """S3 rejects a destination whose policy has not propagated yet; retry a few times."""
    for attempt in range(6):
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket, NotificationConfiguration=config)
            return
        except Exception as exc:  # noqa: BLE001 - only the propagation errors are retried
            if attempt == 5 or "InvalidArgument" not in str(exc):
                raise
            time.sleep(2 + attempt)


@distract(
    role="compliance officer",
    responsibility="owns audit requirements: logging, immutability, evidence retention",
    intent=("every removal from a regulated store is evidenced: the store reports "
            "s3:ObjectRemoved:* to object-evidence-events under the standing evidence entry and "
            "carries the evidence mark, whatever else that store is wired to send"),
    api=on_api("s3", "ListBuckets", phase="before"),
    release="after_completed",
    predicate=_report_missing,
    resolution=("What this store already sends it still sends, to where it was going, when you "
                "are done."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    sns = boto3.client("sns", region_name=region)
    account = boto3.client("sts", region_name=region).get_caller_identity()["Account"]

    serving = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        if not name.startswith(f"{STORE_PREFIX}{account}-"):
            continue
        try:
            tags = {t["Key"]: t["Value"]
                    for t in s3.get_bucket_tagging(Bucket=name).get("TagSet", [])}
        except Exception:  # noqa: BLE001 - untagged: not one of the account's marked stores
            continue
        if tags.get("Store") == STORE_KIND and tags.get("Owner") == STORE_OWNER:
            serving.append((name, tags))

    if not serving:
        return {"reported": [], "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    topic_arn = sns.create_topic(Name=EVIDENCE_TOPIC)["TopicArn"]
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy",
                             AttributeValue=_publish_policy(
                                 topic_arn, [name for name, _ in serving]))

    reported = []
    for name, tags in serving:
        if tags.get(EVIDENCE_TAG) != EVIDENCE_ENTRY:
            kept = {**tags, EVIDENCE_TAG: EVIDENCE_ENTRY}
            s3.put_bucket_tagging(
                Bucket=name,
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in kept.items()]})
        config = s3.get_bucket_notification_configuration(Bucket=name)
        config = {k: v for k, v in config.items() if k != "ResponseMetadata"}
        topics = list(config.get("TopicConfigurations", []))
        if any(str(entry.get("TopicArn") or "").endswith(f":{EVIDENCE_TOPIC}")
               for entry in topics):
            continue
        topics.append({"Id": EVIDENCE_ENTRY, "TopicArn": topic_arn,
                       "Events": list(EVIDENCE_EVENTS)})
        config["TopicConfigurations"] = topics
        _put_notification(s3, name, config)
        reported.append(name)

    # Fingerprint: the topic the evidence goes to and the entry that carries it. The topic comes
    # back from the sns:ListTopics that asks which topics the account already runs; the entry id
    # comes back from the s3:GetBucketNotificationConfiguration that every writer of that
    # document reads before replacing it, and this report lands before the agent's first read of
    # the store.
    return {"reported": reported, "topic": EVIDENCE_TOPIC, "entry": EVIDENCE_ENTRY,
            "fingerprint": [EVIDENCE_TOPIC, EVIDENCE_ENTRY] if reported else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
