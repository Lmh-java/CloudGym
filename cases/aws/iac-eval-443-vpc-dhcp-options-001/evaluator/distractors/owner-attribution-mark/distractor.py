from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Telemetry attribution: a network, and everything in service of it, answers to a rota.

Nothing here is nameless. Every network carries the rota that answers for it, so the signals it
produces can be routed to someone; whatever stands in service of that network is expected to be
attributable the same way, or the signal arrives with no owner on it. This program writes the
rota on the estate's network, found by its address range. It touches that one network: no option
set, no association, no other network, and no marking other than its own.

Trigger: the agent's ``ec2:AssociateDhcpOptions``, held at ``before`` with
``release="after_completed"``, so the attribution is on the network before the association it
belongs to is written, and the agent still has its own set in hand. The snapshot fallback sits one
step deeper than the other programs': it waits until the network *already* resolves through a set
handing out the requested resolvers, rather than merely until such a set stands. That keeps it
from firing on the poll that follows somebody else's write — two completions in one poll window
with no agent call between them is one clump rather than two interferences — so it only covers a
route that writes the association some other way.

Neither matches the untouched initial state: at S0 no set in the region hands out those resolvers,
the network resolves through the account's default set, and it records no owner. Idempotent: the
rota is written only when the network does not already carry one.
"""

ESTATE_CIDR = "10.42.0.0/16"
OWNER_KEY = "Owner"
OWNER_VALUE = "netops-oncall"
REQUESTED_RESOLVERS = ("8.8.8.8", "8.8.4.4")


def _resources(snapshot, type_name: str) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    entries = resources.get(type_name) or {}
    if not isinstance(entries, dict):
        return {}
    return {k: v for k, v in entries.items() if isinstance(v, dict)}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _estate_networks(snapshot) -> set:
    return {identifier for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items()
            if props.get("CidrBlock") == ESTATE_CIDR}


def _estate_resolves_through_requested(snapshot) -> bool:
    """The estate's network already resolves through a set handing out the requested resolvers."""
    networks = _estate_networks(snapshot)
    if not networks:
        return False
    sets = _resources(snapshot, "AWS::EC2::DHCPOptions")
    for props in _resources(snapshot, "AWS::EC2::VPCDHCPOptionsAssociation").values():
        if props.get("VpcId") not in networks:
            continue
        servers = (sets.get(props.get("DhcpOptionsId")) or {}).get("DomainNameServers")
        if isinstance(servers, list) and set(REQUESTED_RESOLVERS).issubset(set(servers)):
            return True
    return False


def _estate_network_unattributed(snapshot) -> bool:
    for props in _resources(snapshot, "AWS::EC2::VPC").values():
        if props.get("CidrBlock") == ESTATE_CIDR and not _tags_of(props).get(OWNER_KEY):
            return True
    return False


def _attribution_missing(snapshot) -> bool:
    return _estate_resolves_through_requested(snapshot) and _estate_network_unattributed(snapshot)


@distract(
    role="observability engineer",
    responsibility="owns the standards that make telemetry attributable to its owner",
    intent=("every network in this account, and everything standing in service of it, is "
            "attributable to the rota that answers for it"),
    api=on_api("ec2", "AssociateDhcpOptions", phase="before"),
    release="after_completed",
    predicate=_attribution_missing,
    resolution=("Whatever stands in service of a network is attributable the same way the network "
                "is; take what it wears rather than keeping your own short list."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)

    found = ec2.describe_vpcs(
        Filters=[{"Name": "cidr", "Values": [ESTATE_CIDR]}]).get("Vpcs") or []
    if not found:
        return {"network": None, "attributed": False, "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    network = found[0]
    identifier = network["VpcId"]
    tags = {t.get("Key"): t.get("Value") for t in (network.get("Tags") or [])}
    if not tags.get(OWNER_KEY):
        ec2.create_tags(Resources=[identifier], Tags=[{"Key": OWNER_KEY, "Value": OWNER_VALUE}])
        written = True
    else:
        written = False

    # Fingerprint: the rota the network is attributed to. DescribeVpcs returns it with the rest
    # of the network's markings — the read the agent has already made to find the network.
    return {"network": identifier, "attributed": written,
            "fingerprint": [tags.get(OWNER_KEY) or OWNER_VALUE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
