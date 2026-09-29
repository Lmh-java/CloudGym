from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Shared edge ACL: this account keeps one network ACL per network for that network's
traffic rules, and workloads put their rules on it rather than standing up a second set.
The platform engineer stands that ACL up for the application network 10.0.0.0/16 as soon
as the network exists, names it and marks it as the edge policy the account keeps. It is
idempotent: where an ACL in that network already carries the mark, it leaves everything
alone.

Fires after the application network is created (CreateVpc, after_success, held until the
program has finished, so the account's ACL is already there when the network's first
traffic rules are written), or when a snapshot shows the network standing with no ACL of
the account's in it. Never fires on the untouched initial state: at S0 the account holds
only the shared-services network 10.3.0.0/16 and its default ACL — no 10.0.0.0/16 network
exists at all.
"""

APP_CIDR = "10.0.0.0/16"
ACL_NAME = "app-edge-acl"
EDGE_KEY = "EdgePolicy"
EDGE_VALUE = "account-edge-baseline"
SETTLE_S = 2.0
ATTEMPTS = 3


# --- the snapshot trigger ------------------------------------------------------


def _app_vpc_ids(snapshot) -> set:
    out = set()
    for identifier, props in (snapshot.get("resources", {}).get("AWS::EC2::VPC") or {}).items():
        if isinstance(props, dict) and props.get("CidrBlock") == APP_CIDR:
            out.add(identifier)
    return out


def _tagged(props, key, value) -> bool:
    for tag in props.get("Tags") or []:
        if isinstance(tag, dict) and tag.get("Key") == key and tag.get("Value") == value:
            return True
    return False


def _network_without_kept_acl(snapshot) -> bool:
    """The application network stands, and no ACL in it is the one the account keeps."""
    vpcs = _app_vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in (snapshot.get("resources", {}).get("AWS::EC2::NetworkAcl") or {}).values():
        if not isinstance(props, dict) or props.get("VpcId") not in vpcs:
            continue
        if _tagged(props, EDGE_KEY, EDGE_VALUE):
            return False
    return True


# --- the account's ACL for a network -------------------------------------------


def _vpc_id(ec2) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": [APP_CIDR]}])["Vpcs"]
    return vpcs[0]["VpcId"] if vpcs else ""


def _kept_acl(ec2, vpc_id) -> str:
    acls = ec2.describe_network_acls(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "tag:" + EDGE_KEY, "Values": [EDGE_VALUE]},
    ])["NetworkAcls"]
    return acls[0]["NetworkAclId"] if acls else ""


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent="the traffic rules of the 10.0.0.0/16 application network live on the one network ACL this account keeps for that network, and no second ACL of a workload's own governs it",
    api=on_api("ec2", "CreateVpc", phase="after_success",
               where=lambda params: params.get("CidrBlock") == APP_CIDR),
    release="after_completed",
    predicate=_network_without_kept_acl,
    resolution="That network's traffic rules are the ones this account keeps for it — put your work on those rather than standing up a set of your own.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))

    vpc_id = ""
    for _ in range(ATTEMPTS):
        vpc_id = _vpc_id(ec2)
        if vpc_id:
            break
        time.sleep(SETTLE_S)
    if not vpc_id:
        return {"changed": [], "reason": "the application network does not exist",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    kept = _kept_acl(ec2, vpc_id)
    if kept:
        return {"changed": [], "kept": kept, "reason": "this network already has the account's ACL",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    kept = ec2.create_network_acl(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "network-acl", "Tags": [
            {"Key": "Name", "Value": ACL_NAME},
            {"Key": EDGE_KEY, "Value": EDGE_VALUE},
        ]}],
    )["NetworkAcl"]["NetworkAclId"]

    # The name and the mark both come back from a describe of the network's ACLs, which is
    # the read anything working on those rules makes.
    return {"changed": [kept], "kept": kept,
            "fingerprint": [EDGE_VALUE, ACL_NAME],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
