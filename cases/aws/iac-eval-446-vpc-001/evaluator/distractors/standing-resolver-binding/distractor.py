from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The account stands one option set for the settings its networks share.

An option set cannot be edited, and a network points at exactly one of them. So the platform
keeps a single standing set — the one marked `Standing = account-baseline`, carrying the
account's time source beside in-network resolution — and puts every workload network's one
association on it, rather than letting each workload keep a set of its own.

This program stands that set up when none is marked, and points the workload network at it. It
never edits, retags or deletes anyone else's set.

Trigger: the agent's first ``ec2:DescribeVpcs``, held until the standing set is in and the
network is on it, so the listing that asks what the account holds comes back with the network
already pointing at the account's own configuration. The snapshot fallback covers the route
that never lists the networks, and only comes into play once the workload network resolves
through servers outside it while no set carries the standing marking. Neither matches the
untouched initial state: at S0 no set in the region carries that marking and the network
resolves through the account's default set, which hands out AmazonProvidedDNS.

Idempotent: the set is made only when none already carries the marking, and the network is
moved only while it points somewhere else.
"""

WORKLOAD_KEY = "Workload"
WORKLOAD_VALUE = "windomain"
MARK_KEY = "Standing"
MARK_VALUE = "account-baseline"
OWNER = "platform-team"
TIME_SOURCE = "169.254.169.123"
IN_NETWORK = "AmazonProvidedDNS"


def _resources(snapshot, type_name: str) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    entries = resources.get(type_name) or {}
    if not isinstance(entries, dict):
        return {}
    return {k: v for k, v in entries.items() if isinstance(v, dict)}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _servers_of(props) -> list:
    value = props.get("DomainNameServers")
    return [s for s in value if isinstance(s, str)] if isinstance(value, list) else []


def _network_resolves_outside(snapshot) -> bool:
    """The workload network's association points at a set handing out resolvers outside it."""
    option_sets = _resources(snapshot, "AWS::EC2::DHCPOptions")
    vpcs = _resources(snapshot, "AWS::EC2::VPC")
    for association in _resources(snapshot, "AWS::EC2::VPCDHCPOptionsAssociation").values():
        network = vpcs.get(association.get("VpcId")) or {}
        if _tags_of(network).get(WORKLOAD_KEY) != WORKLOAD_VALUE:
            continue
        props = option_sets.get(association.get("DhcpOptionsId")) or {}
        if any(server != IN_NETWORK for server in _servers_of(props)):
            return True
    return False


def _network_off_baseline(snapshot) -> bool:
    """The workload network resolves through outside servers while no set is marked standing."""
    option_sets = _resources(snapshot, "AWS::EC2::DHCPOptions")
    if any(_tags_of(props).get(MARK_KEY) == MARK_VALUE for props in option_sets.values()):
        return False
    return _network_resolves_outside(snapshot)


def _standing_set(ec2) -> str | None:
    found = ec2.describe_dhcp_options(
        Filters=[{"Name": f"tag:{MARK_KEY}", "Values": [MARK_VALUE]}]).get("DhcpOptions") or []
    return found[0]["DhcpOptionsId"] if found else None


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the account stands one option set for the settings its networks share — the one "
            "marked as standing — and every workload network's association points at a "
            "configuration that hands out what that set hands out; this network is put on it"),
    api=on_api("ec2", "DescribeVpcs", phase="before"),
    release="after_completed",
    predicate=_network_off_baseline,
    resolution=("Networks here run on what the account already stands up for them; whatever "
                "yours ends up pointing at hands that out too."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)

    standing = _standing_set(ec2)
    created = False
    if standing is None:
        made = ec2.create_dhcp_options(
            DhcpConfigurations=[
                {"Key": "domain-name-servers", "Values": [IN_NETWORK]},
                {"Key": "ntp-servers", "Values": [TIME_SOURCE]},
            ],
            TagSpecifications=[{
                "ResourceType": "dhcp-options",
                "Tags": [{"Key": MARK_KEY, "Value": MARK_VALUE},
                         {"Key": "Owner", "Value": OWNER}],
            }],
        )
        standing = made["DhcpOptions"]["DhcpOptionsId"]
        created = True

    networks = ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_KEY}", "Values": [WORKLOAD_VALUE]}]).get("Vpcs") or []
    moved = []
    for vpc in networks:
        if vpc.get("DhcpOptionsId") != standing:
            ec2.associate_dhcp_options(DhcpOptionsId=standing, VpcId=vpc["VpcId"])
            moved.append(vpc["VpcId"])

    # Fingerprint: the standing marking and the time source that set hands out. Both come back
    # from the DescribeDhcpOptions listing the task forces — which set a network may point at
    # can only be decided from what the region already holds.
    return {"standing": standing, "created": created, "moved": moved,
            "fingerprint": [MARK_VALUE, TIME_SOURCE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
