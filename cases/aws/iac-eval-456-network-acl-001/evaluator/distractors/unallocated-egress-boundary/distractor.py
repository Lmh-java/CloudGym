from __future__ import annotations

import json
import os
import time

from harness.runtime import distract, on_api

"""Unallocated egress boundary: nothing in the application network may reach out into
partner address space that no segment is allocated in. The network security engineer keeps
that boundary on every ACL governing the 10.0.0.0/16 network — an outbound deny for
10.3.32.0/19, all protocols, at the slot it appends its boundaries to — and marks the ACL
with the boundary it maintains. Entries are matched in ascending rule number, so a wider
outbound allowance written at a lower slot reaches straight past the boundary; the program
takes its own slot back if something else holds it and changes nothing else.

Fires after the second traffic rule is written for that network (CreateNetworkAclEntry,
after_success, second occurrence, held until the program has finished), or when a snapshot
shows an ACL of that network reaching out to the partner range with no boundary on the
unallocated space — both of which come after the network's inbound rules are written, so
this boundary lands as its own event rather than alongside them. Never fires on the untouched initial state: at S0 there is no 10.0.0.0/16
network, no ACL governing one, and the only allocated segment of the partner range sits in
the shared-services network.
"""

APP_CIDR = "10.0.0.0/16"
UNALLOCATED = "10.3.32.0/19"
PARTNER_RANGE = "10.3.0.0/18"
BOUNDARY_RULE = 300
BOUNDARY_KEY = "EgressBoundary"
BOUNDARY_VALUE = "unallocated-space-closed"
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


def _reaches_partner_range(props) -> bool:
    """This network has been given a way out to the partner range — what bounds apply to."""
    for entry in _entries(props):
        if entry.get("Egress") and entry.get("RuleAction") == "allow" \
                and str(entry.get("CidrBlock")) in (PARTNER_RANGE, UNALLOCATED):
            return True
    return False


def _holds_boundary(props) -> bool:
    for entry in _entries(props):
        if entry.get("Egress") and entry.get("RuleAction") == "deny" \
                and str(entry.get("CidrBlock")) == UNALLOCATED:
            return True
    return False


def _boundary_missing(snapshot) -> bool:
    """An ACL of the application network reaches out to the partner range unbounded."""
    for props in _app_acls(snapshot):
        if _reaches_partner_range(props) and not _holds_boundary(props):
            return True
    return False


# --- writing the boundary -------------------------------------------------------


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
    role="network security engineer",
    responsibility="owns egress control: which paths out of the network may exist",
    intent="the 10.0.0.0/16 application network has no outbound path into 10.3.32.0/19, the partner address space no segment is allocated in: on every ACL governing that network the entry denying it outbound is the first one matching it",
    api=on_api("ec2", "CreateNetworkAclEntry", phase="after_success", occurrence=2),
    release="after_completed",
    predicate=_boundary_missing,
    resolution="The way out I keep closed on that network stays closed — nothing you add there may reach past it.",
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

    spec = {"RuleNumber": BOUNDARY_RULE, "Protocol": "-1", "RuleAction": "deny",
            "Egress": True, "CidrBlock": UNALLOCATED}
    changed = []
    for acl_id in targets:
        outcome = _put(ec2, acl_id, spec)
        ec2.create_tags(Resources=[acl_id], Tags=[{"Key": BOUNDARY_KEY, "Value": BOUNDARY_VALUE}])
        if outcome != "kept":
            changed.append(acl_id)

    # The closed space shows up in the entry list and the boundary in the tags of the same
    # describe of the network's ACLs.
    return {"changed": changed, "bounded": targets,
            "fingerprint": [BOUNDARY_VALUE, UNALLOCATED],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
