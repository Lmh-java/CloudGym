from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Platform: everything the checkout service owns carries the account's cost-allocation record.

The account's standard records say who pays for a resource as well as whose it is, so the store
the checkout service keeps its events in and the identity the service runs as both carry the
service's code from here on. Nothing else on either is touched — the records already there stay
as they are.

Fires when the agent writes the grant as an inline policy on the identity (held until this
program has finished, so the identity comes back already stamped). The other way to grant is a
managed policy attached to the identity, which that anchor cannot see, and that is exactly what
the snapshot fallback covers: the identity holds an attached policy and no inline one at all, a
store stands beside `checkout-events`, and `checkout-events` carries no cost-allocation record.
The two are mutually exclusive by construction — a route that writes the grant inline never
satisfies the fallback, so the fallback cannot fire alongside the anchor it stands in for.
Never fires on the untouched initial state: at S0 the account holds exactly one table and the
identity holds nothing, attached or inline.

Idempotent: a second firing finds both marks already there and rewrites the same value.
"""

SOURCE = "checkout-events"
ROLE = "checkout-service"
RECORD_KEY = "CostCenter"
RECORD_VALUE = "CHK-4471"
ATTEMPTS = 12
DELAY = 4


def _tables(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    tables = resources.get("AWS::DynamoDB::Table") or {}
    return tables if isinstance(tables, dict) else {}


def _roles(snapshot) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    roles = resources.get("AWS::IAM::Role") or {}
    return roles if isinstance(roles, dict) else {}


def _records(props) -> dict:
    out = {}
    for tag in (props or {}).get("Tags") or []:
        if isinstance(tag, dict) and "Key" in tag:
            out[tag["Key"]] = tag.get("Value")
    return out


def _granted_by_attachment_only(snapshot) -> bool:
    """The identity was granted through an attached policy rather than an inline one.

    This is the one route the API anchor is blind to. Requiring *no* inline policy is what
    keeps the fallback and the anchor apart: on a route that writes the grant inline the
    fallback is false for the whole run, so the two can never fire on the same work.
    """
    props = _roles(snapshot).get(ROLE) or {}
    return bool(props.get("ManagedPolicyArns")) and not props.get("Policies")


def _second_store_stands(snapshot) -> bool:
    """The agent's own store: a table other than the one the service already keeps."""
    return any(name != SOURCE for name in _tables(snapshot))


def _source_unallocated(snapshot) -> bool:
    if not (_second_store_stands(snapshot) and _granted_by_attachment_only(snapshot)):
        return False
    props = _tables(snapshot).get(SOURCE)
    if props is None:
        return False
    return _records(props).get(RECORD_KEY) != RECORD_VALUE


@distract(
    role="platform engineer",
    responsibility="owns tag standards and the values every resource must carry",
    intent=("everything the checkout service owns carries the account's cost-allocation record "
            "alongside the records that say whose it is: the store checkout-events and the "
            "identity checkout-service both carry the service's code"),
    api=on_api("iam", "PutRolePolicy"),
    release="after_completed",
    predicate=_source_unallocated,
    resolution=("Every store here carries the account's standard records; a store holding the "
                "same data carries what that data's store carries."),
)
def run() -> dict:
    import time

    import boto3
    from botocore.exceptions import ClientError

    ddb = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION"))
    iam = boto3.client("iam")

    arn = ddb.describe_table(TableName=SOURCE)["Table"]["TableArn"]
    carried = {tag["Key"]: tag["Value"]
               for tag in ddb.list_tags_of_resource(ResourceArn=arn).get("Tags") or []}
    if carried.get(RECORD_KEY) != RECORD_VALUE:
        # A store's records are written one at a time: whoever else is recording something on
        # this store holds the lock for a few seconds.
        for attempt in range(ATTEMPTS):
            try:
                ddb.tag_resource(ResourceArn=arn,
                                 Tags=[{"Key": RECORD_KEY, "Value": RECORD_VALUE}])
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code not in ("LimitExceededException", "ResourceInUseException",
                                "ThrottlingException") or attempt == ATTEMPTS - 1:
                    raise
                time.sleep(DELAY)

    stamped_identity = False
    try:
        on_role = {tag["Key"]: tag["Value"]
                   for tag in iam.list_role_tags(RoleName=ROLE).get("Tags") or []}
        if on_role.get(RECORD_KEY) != RECORD_VALUE:
            iam.tag_role(RoleName=ROLE, Tags=[{"Key": RECORD_KEY, "Value": RECORD_VALUE}])
        stamped_identity = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

    # Fingerprint: the code both the store and the identity carry from here on — it comes back
    # with the records of the store and with the identity the grant is written on.
    return {"store": SOURCE, "identity": ROLE if stamped_identity else None,
            "allocated_to": RECORD_VALUE, "fingerprint": [RECORD_VALUE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
