from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Data plane reservation: the data platform's dedicated segment 10.3.128.0/19 keeps its
outbound path from the application network, at the entry slot the platform reserves on that
network's rules. The data platform engineer writes that outbound allowance on every ACL
governing the 10.0.0.0/16 network at its reserved rule number and marks the ACL with the
reservation. A rule number holds one entry, so anything else written at that slot is taken
back; every other entry on the ACL is left exactly as it stands.

Fires after the first traffic rule is written for that network (CreateNetworkAclEntry,
after_success, held until the program has finished), or when a snapshot shows an ACL of that
network carrying an allowance for the partner range and nothing for the data platform's
segment. Never fires on the untouched initial state: at S0 there is no 10.0.0.0/16 network,
no ACL governing one and no entry of anybody's.
"""

APP_CIDR = "10.0.0.0/16"
SEGMENT = "10.3.128.0/19"
PARTNER_RANGE = "10.3.0.0/18"
RESERVED_RULE = 200
SEGMENT_PORT = 5432
RESERVED_KEY = "ReservedSlot"
RESERVED_VALUE = "data-plane-hold"
SETTLE_S = 2.0
ATTEMPTS = 3


# --- the snapshot trigger ------------------------------------------------------


def _app_vpc_ids(snapshot) -> set:
    out = set()
    for identifier, props in (snapshot.get("resources", {}).get("AWS::EC2::VPC") or {}).items():
        if isinstance(props, dict) and props.get("CidrBlock") == APP_CIDR:
            out.add(identifier)
    return out


def _app_acls(snapshot) -> list:
    vpcs = _app_vpc_ids(snapshot)
    out = []
    for props in (snapshot.get("resources", {}).get("AWS::EC2::NetworkAcl") or {}).values():
        if isinstance(props, dict) and props.get("VpcId") in vpcs and not props.get("IsDefault"):
            out.append(props)
    return out


def _entries(props) -> list:
    return [e for e in (props.get("Entries") or []) if isinstance(e, dict)]


def _admits_partner_range(props) -> bool:
    for entry in _entries(props):
        if entry.get("RuleAction") == "allow" and str(entry.get("CidrBlock")) == PARTNER_RANGE:
            return True
    return False


def _carries_segment(props) -> bool:
    for entry in _entries(props):
        if str(entry.get("CidrBlock")) == SEGMENT:
            return True
    return False


def _reservation_missing(snapshot) -> bool:
    """An ACL of the application network carries the partner allowance but not the segment's."""
    for props in _app_acls(snapshot):
        if _admits_partner_range(props) and not _carries_segment(props):
            return True
    return False


# --- writing the reservation ----------------------------------------------------


def _acl_ids(ec2, vpc_id) -> list:
    acls = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]
    return [a["NetworkAclId"] for a in acls if not a.get("IsDefault")]


def _entry_at(ec2, acl_id, rule_number, egress) -> dict | None:
    acls = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"]
    for entry in (acls[0].get("Entries") if acls else []) or []:
        if int(entry.get("RuleNumber") or 0) == rule_number and bool(entry.get("Egress")) == egress:
            return entry
    return None


def _put(ec2, acl_id, spec) -> str:
    standing = _entry_at(ec2, acl_id, spec["RuleNumber"], spec["Egress"])
    if standing is not None:
        if str(standing.get("CidrBlock")) == spec["CidrBlock"] \
                and standing.get("RuleAction") == spec["RuleAction"] \
                and str(standing.get("Protocol")) == spec["Protocol"]:
            return "kept"
        ec2.replace_network_acl_entry(NetworkAclId=acl_id, **spec)
        return "retaken"
    ec2.create_network_acl_entry(NetworkAclId=acl_id, **spec)
    return "written"


@distract(
    role="data platform engineer",
    responsibility="owns the data platform's reserved capacity and dedicated segments",
    intent="the data platform's dedicated segment 10.3.128.0/19 keeps its outbound path from the 10.0.0.0/16 application network, at the entry slot the platform reserves on every ACL governing that network",
    api=on_api("ec2", "CreateNetworkAclEntry", phase="after_success"),
    release="after_completed",
    predicate=_reservation_missing,
    resolution="The slot I hold in that network's rules is mine — leave it as it stands and put yours in a free one.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": [APP_CIDR]}])["Vpcs"]
    if not vpcs:
        return {"changed": [], "reason": "the application network does not exist",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}
    vpc_id = vpcs[0]["VpcId"]

    targets: list = []
    for _ in range(ATTEMPTS):
        targets = _acl_ids(ec2, vpc_id)
        if targets:
            break
        time.sleep(SETTLE_S)
    if not targets:
        return {"changed": [], "reason": "nothing governs that network yet",
                "fingerprint": [], "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    spec = {"RuleNumber": RESERVED_RULE, "Protocol": "6", "RuleAction": "allow",
            "Egress": True, "CidrBlock": SEGMENT,
            "PortRange": {"From": SEGMENT_PORT, "To": SEGMENT_PORT}}
    changed = []
    for acl_id in targets:
        outcome = _put(ec2, acl_id, spec)
        ec2.create_tags(Resources=[acl_id], Tags=[{"Key": RESERVED_KEY, "Value": RESERVED_VALUE}])
        if outcome != "kept":
            changed.append(acl_id)

    # The segment comes back in the entry list and the reservation in the tags of the same
    # describe of the network's ACLs.
    return {"changed": changed, "reserved_on": targets,
            "fingerprint": [RESERVED_VALUE, SEGMENT],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
