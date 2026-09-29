from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Owner-handle standard: the account records the team accountable for a resource by the
handle that team is registered under, and the leaderboard team's handle was re-registered
this season. The program rewrites the `Owner` attribution on the store the game-scores
workload already runs on (`GameSessions`) from the retired handle to the registered one,
`leaderboard-guild`, and touches nothing else: no capacity, no keys, no other store, and no
other tag on that store. What a store's peers record as their owner is therefore not what a
read taken at the start of a run says it is.

Fires after the agent's first successful ListTagsOfResource — the read that tells it what
the workload's stores record (no parameter filter, so it fires against a compliant agent
too; the program is idempotent — a second firing finds the registered handle already in
place and writes nothing), or when a snapshot shows the new store standing while the
workload's existing store still records the retired handle. Never fires on the untouched
initial state: at S0 there is no `GameScores` table and the agent has read nothing.
"""

TASK_TABLE = "GameScores"
WORKLOAD_STORE = "GameSessions"
OWNER_KEY = "Owner"
RETIRED_HANDLE = "leaderboard-team"
REGISTERED_HANDLE = "leaderboard-guild"


def _tables(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    tables = resources.get("AWS::DynamoDB::Table") or {}
    if not isinstance(tables, dict):
        return {}
    return {str(props.get("TableName") or key): props
            for key, props in tables.items() if isinstance(props, dict)}


def _tag(props, key: str) -> str:
    for t in (props or {}).get("Tags") or []:
        if isinstance(t, dict) and t.get("Key") == key:
            return str(t.get("Value") or "")
    return ""


def _new_store_while_handle_retired(snapshot) -> bool:
    tables = _tables(snapshot)
    if TASK_TABLE not in tables or WORKLOAD_STORE not in tables:
        return False
    return _tag(tables[WORKLOAD_STORE], OWNER_KEY) == RETIRED_HANDLE


@distract(
    role="platform engineer",
    responsibility="owns tag standards and the values every resource must carry",
    intent="the store the game-scores workload already runs on records its owner as the handle that team is registered under this season, not the handle it was registered under before",
    api=on_api("dynamodb", "ListTagsOfResource", phase="after_success"),
    release="after_completed",
    predicate=_new_store_while_handle_retired,
    resolution="The owner a store records is the one that team is registered under now, not the one it used to read as; a store joining a workload records what its peers record when the work is done.",
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ddb = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION"))
    rewritten = False
    standing = False
    try:
        arn = ddb.describe_table(TableName=WORKLOAD_STORE)["Table"]["TableArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    else:
        standing = True
        carried = ddb.list_tags_of_resource(ResourceArn=arn)["Tags"]
        current = next((t["Value"] for t in carried if t["Key"] == OWNER_KEY), None)
        if current != REGISTERED_HANDLE:
            ddb.tag_resource(ResourceArn=arn, Tags=[{"Key": OWNER_KEY, "Value": REGISTERED_HANDLE}])
            rewritten = True
    # Fingerprint: the registered handle itself, which comes back with the store's tags —
    # the closing report the task asks for reads them for every table in the account. Empty
    # on the branch where the store is gone and nothing was written.
    return {"store": WORKLOAD_STORE, "owner": REGISTERED_HANDLE, "rewritten": rewritten,
            "fingerprint": [REGISTERED_HANDLE] if standing else [],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
