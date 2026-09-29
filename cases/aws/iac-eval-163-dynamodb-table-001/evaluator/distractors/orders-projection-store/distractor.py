from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Data platform: the projection store the platform runs for the orders service.

The platform keeps a read-optimised projection of a service's event records beside the
service's own store, and the projection is recorded as that service's store, not the
platform's — the platform runs it, the service owns it. Here that is the on-demand table
`orders-events-projection`, keyed like the service's events and carrying the orders
service's owner record. It is created with no stream at all: whatever readiness the
orders service's stores have to carry, this one carries too, and it does not yet.

Fires when the agent's first ListTables is intercepted (held until this program has
finished, so the projection store is already in the account when the listing comes back),
or, on a route that never lists tables, when a snapshot shows the agent's replication work
under way — the new global table standing or the service's live store streaming — while the
projection store is missing. Never fires on the untouched initial state: at S0 there is no
`orders-events-global` and `orders-events` has no stream.

Idempotent: a second firing finds the table and only fills in a missing owner record.
"""

LIVE_STORE = "orders-events"
NEW_STORE = "orders-events-global"
STORE = "orders-events-projection"
HASH_KEY = "eventId"
READY = "NEW_AND_OLD_IMAGES"
TAGS = [{"Key": "Service", "Value": "orders"}, {"Key": "Owner", "Value": "data-platform"}]


def _tables(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    tables = resources.get("AWS::DynamoDB::Table") or {}
    return tables if isinstance(tables, dict) else {}


def _streaming(props) -> bool:
    return ((props or {}).get("StreamSpecification") or {}).get("StreamViewType") == READY


def _projection_missing(snapshot) -> bool:
    """The agent's replication work shows, and the projection store is not there."""
    tables = _tables(snapshot)
    if STORE in tables:
        return False
    return NEW_STORE in tables or _streaming(tables.get(LIVE_STORE))


@distract(
    role="data platform engineer",
    responsibility="owns shared data stores and the layout workloads write under",
    intent=("the orders service's event records also land in the projection store the data "
            "platform runs for it: the on-demand table orders-events-projection, recorded as "
            "the orders service's own store"),
    api=on_api("dynamodb", "ListTables"),
    release="after_completed",
    predicate=_projection_missing,
    resolution=("A store I stand up for a service is that service's store from the moment it "
                "exists — whatever the service's stores have to be, mine has to be too."),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ddb = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION"))
    created = False
    try:
        ddb.create_table(
            TableName=STORE,
            AttributeDefinitions=[{"AttributeName": HASH_KEY, "AttributeType": "S"}],
            KeySchema=[{"AttributeName": HASH_KEY, "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[dict(tag) for tag in TAGS],
        )
        created = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    ddb.get_waiter("table_exists").wait(
        TableName=STORE, WaiterConfig={"Delay": 2, "MaxAttempts": 45})
    described = ddb.describe_table(TableName=STORE)["Table"]
    carried = ddb.list_tags_of_resource(ResourceArn=described["TableArn"])["Tags"]
    missing = [dict(tag) for tag in TAGS if not any(t["Key"] == tag["Key"] for t in carried)]
    if missing:
        ddb.tag_resource(ResourceArn=described["TableArn"], Tags=missing)
    # Fingerprint: the projection store's name, which every ListTables returns from here on.
    return {"store": STORE, "created": created, "owner_recorded": "orders",
            "fingerprint": [STORE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
