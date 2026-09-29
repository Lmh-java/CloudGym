from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The boundary on what may reach into a network of this account from outside.

Nothing outside this account's own address space reaches into a network of this account. On the
list a network hands a segment by default that comes to one entry: every protocol admitted from
the account's own space and nothing beyond it, at the boundary's own slot, with the list marked so
the boundary it stands under is readable off it. Anything already admitting a wider source is
taken off the list; entries that admit nothing wider are left alone.

Trigger: the agent's first successful ``ec2:CreateSubnet`` — the network is being filled, so what
may reach into it is about to matter — held until the boundary has landed, so the allowance and
the marks are on the list before anything is written to it. The snapshot fallback is the agent
having started in the network (a segment at the first range the task names is cut) while the list
that network hands a segment by default carries no inbound-boundary mark. Neither matches the
untouched initial state: at S0 nothing has been created, the network is empty and the list carries
no mark of anyone's.

Idempotent: the allowance is written only when the boundary's slot is not already carrying it,
whatever else took that slot comes off first, the widening entries are removed only while any
remain, and the marks are re-applied rather than assumed to have stood.
"""

VPC_CIDR = "10.40.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "pike"
FIRST_SEGMENT = "10.40.1.0/24"

ACCOUNT_SPACE = "10.0.0.0/8"
BOUNDARY_RULE = 110
INBOUND_TAG = "Inbound"
INBOUND_BOUNDARY = "account-space-only"
INBOUND_REFERENCE_TAG = "InboundRef"
INBOUND_REFERENCE = "NSE-4412"

BOUNDARY_MARKS = [
    {"Key": INBOUND_TAG, "Value": INBOUND_BOUNDARY},
    {"Key": INBOUND_REFERENCE_TAG, "Value": INBOUND_REFERENCE},
]

# Sources outside the account's own space, as they are written on a list. Anything an inbound
# allow entry names that is not inside the account's space widens the boundary; these are the
# forms that actually turn up.
_ACCOUNT_PREFIX = "10."


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _pike_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _work_started(snapshot, vpcs: set) -> bool:
    for _identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items():
        props = props or {}
        if props.get("VpcId") in vpcs and props.get("CidrBlock") == FIRST_SEGMENT:
            return True
    return False


def _boundary_absent(snapshot) -> bool:
    vpcs = _pike_vpc_ids(snapshot)
    if not vpcs:
        return False
    for _identifier, props in _resources(snapshot, "AWS::EC2::NetworkAcl").items():
        props = props or {}
        if props.get("VpcId") not in vpcs or not props.get("IsDefault"):
            continue
        if _tag(props, INBOUND_TAG) == INBOUND_BOUNDARY:
            return False
    return _work_started(snapshot, vpcs)


def _widens(entry) -> bool:
    """An inbound allow entry naming a source outside the account's own space."""
    if bool(entry.get("Egress")) or entry.get("RuleAction") != "allow":
        return False
    if int(entry.get("RuleNumber") or 0) >= 32767:
        return False
    cidr = entry.get("CidrBlock")
    if not cidr:
        return True
    return not cidr.startswith(_ACCOUNT_PREFIX)


@distract(
    role="network security engineer",
    responsibility="owns ingress exposure: what may ever be reachable, from where",
    intent=("nothing outside this account's own address space reaches into a network of this "
            "account: the list that network hands a segment by default admits every protocol from "
            "the account's own space and carries no inbound allowance naming a wider source"),
    api=on_api("ec2", "CreateSubnet", phase="after_success"),
    release="after_completed",
    predicate=_boundary_absent,
    resolution=(
        "What this network takes in from outside is already settled where it stands; nothing you "
        "add may let in more than that."
    ),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    networks = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not networks:
        return {"bounded": None, "note": f"no network on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(networks, key=lambda v: v["VpcId"])[0]["VpcId"]

    lists = [a for a in ec2.describe_network_acls(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"] if a.get("IsDefault")]
    if not lists:
        return {"bounded": None, "note": "the network hands a segment no list by default",
                "fingerprint": [], "trigger": trigger}
    default_list = sorted(lists, key=lambda a: a["NetworkAclId"])[0]
    acl_id = default_list["NetworkAclId"]

    removed = []
    for entry in default_list.get("Entries") or []:
        if not _widens(entry):
            continue
        try:
            ec2.delete_network_acl_entry(NetworkAclId=acl_id, Egress=False,
                                         RuleNumber=int(entry["RuleNumber"]))
            removed.append(int(entry["RuleNumber"]))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidNetworkAclEntry.NotFound":
                raise

    at_slot = [e for e in default_list.get("Entries") or []
               if e.get("RuleNumber") == BOUNDARY_RULE and not e.get("Egress")
               and int(e.get("RuleNumber") or 0) not in removed]
    stood = any(e.get("RuleAction") == "allow" and e.get("CidrBlock") == ACCOUNT_SPACE
                for e in at_slot)
    if not stood:
        if at_slot:
            # The slot the boundary sits at is the boundary's; whatever else took it comes off.
            try:
                ec2.delete_network_acl_entry(NetworkAclId=acl_id, Egress=False,
                                             RuleNumber=BOUNDARY_RULE)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidNetworkAclEntry.NotFound":
                    raise
        try:
            ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=BOUNDARY_RULE,
                                         Protocol="-1", RuleAction="allow", Egress=False,
                                         CidrBlock=ACCOUNT_SPACE)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NetworkAclEntryAlreadyExists":
                raise

    ec2.create_tags(Resources=[acl_id], Tags=list(BOUNDARY_MARKS))

    return {"bounded": acl_id, "network": vpc_id, "rule": BOUNDARY_RULE,
            "admits": ACCOUNT_SPACE, "boundary": INBOUND_BOUNDARY,
            "reference": INBOUND_REFERENCE, "removed": removed,
            "note": "boundary already stood" if stood else "boundary applied",
            "fingerprint": [INBOUND_BOUNDARY, INBOUND_REFERENCE], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
