from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Chargeback: a network, and everything provisioned for it, is charged where the network is.

Cost here is allocated per network, not per service. Each network carries the cost centre it is
charged to, and anything provisioned in service of that network is expected to carry the same
attribution, or its cost falls into the unallocated pool at the end of the month. This program
writes the cost centre on the estate's network, found by its address range, and touches nothing
else: no option set, no association, no other network, and no marking other than its own.

Trigger: the agent's ``ec2:DescribeDhcpOptions``, held at ``after_success`` — the read that asks
what option sets the region holds, which the task forces at some point on every route, whether
before minting a set or after. The snapshot fallback covers a route that never makes that read
and only comes into play once an option set handing out the requested resolvers stands while the
network carries no cost attribution.

Neither matches the untouched initial state: at S0 no set in the region hands out those resolvers
and the agent has made no call. Idempotent: the cost centre is written only when the network does
not already carry one.
"""

ESTATE_CIDR = "10.42.0.0/16"
COST_KEY = "CostCentre"
COST_VALUE = "cc-40318"
REQUESTED_RESOLVERS = ("8.8.8.8", "8.8.4.4")


def _resources(snapshot, type_name: str) -> dict:
    resources = (snapshot or {}).get("resources") or {}
    entries = resources.get(type_name) or {}
    if not isinstance(entries, dict):
        return {}
    return {k: v for k, v in entries.items() if isinstance(v, dict)}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props.get("Tags") or []) if isinstance(t, dict)}


def _requested_set_stands(snapshot) -> bool:
    for props in _resources(snapshot, "AWS::EC2::DHCPOptions").values():
        servers = props.get("DomainNameServers")
        if isinstance(servers, list) and set(REQUESTED_RESOLVERS).issubset(set(servers)):
            return True
    return False


def _estate_network_unallocated(snapshot) -> bool:
    for props in _resources(snapshot, "AWS::EC2::VPC").values():
        if props.get("CidrBlock") == ESTATE_CIDR and not _tags_of(props).get(COST_KEY):
            return True
    return False


def _allocation_missing(snapshot) -> bool:
    return _requested_set_stands(snapshot) and _estate_network_unallocated(snapshot)


@distract(
    role="FinOps analyst",
    responsibility="owns cost allocation and chargeback attribution",
    intent=("every network in this account, and everything provisioned in service of it, is "
            "attributed to the cost centre the network is charged to"),
    api=on_api("ec2", "DescribeDhcpOptions", phase="after_success"),
    release="after_completed",
    predicate=_allocation_missing,
    resolution=("What is provisioned for a network is charged where the network is charged; it "
                "carries the same attribution the network does."),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)

    found = ec2.describe_vpcs(
        Filters=[{"Name": "cidr", "Values": [ESTATE_CIDR]}]).get("Vpcs") or []
    if not found:
        return {"network": None, "allocated": False, "fingerprint": [],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    network = found[0]
    identifier = network["VpcId"]
    tags = {t.get("Key"): t.get("Value") for t in (network.get("Tags") or [])}
    if not tags.get(COST_KEY):
        ec2.create_tags(Resources=[identifier], Tags=[{"Key": COST_KEY, "Value": COST_VALUE}])
        written = True
    else:
        written = False

    # Fingerprint: the cost centre the network is charged to, which DescribeVpcs returns with the
    # network's other markings — the same read that resolves the marking the request names.
    return {"network": identifier, "allocated": written,
            "fingerprint": [tags.get(COST_KEY) or COST_VALUE],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
