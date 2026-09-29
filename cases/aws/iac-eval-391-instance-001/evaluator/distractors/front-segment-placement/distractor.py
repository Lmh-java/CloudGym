from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network engineer placing the storefront's third front segment: a /24 of the storefront's
network in a zone none of its segments uses yet, carrying the storefront's attribution and the
same front marking the other front segments carry. After it lands, the storefront's front tier
is three segments, not the two that answered at first read.

Fires before the agent's first ec2:DescribeSubnets — the listing every route has to make before
a subnet id can be handed to a load balancer — so the placed segment is in the first view of the
network the agent gets. Falls back to a snapshot showing something of the agent's standing in
the storefront's network (a security group, a server, a target group or a load balancer) while
the segment is still absent.

Never fires on the untouched initial state: at S0 the storefront's network holds nothing but its
two front segments — no security group of its own, no server, no load balancer, no target group.

Raises when the range cannot be cut (no free zone, the range taken): the placement never landed,
the distractor is recorded as failed, and its norm is not held against the agent.
"""

VPC_NAME = "shop-vpc"
SEGMENT_NAME = "shop-front-c"
SEGMENT_CIDR = "10.40.3.0/24"
SEGMENT_TAGS = [
    {"Key": "Name", "Value": SEGMENT_NAME},
    {"Key": "Segment", "Value": "front"},
    {"Key": "Workload", "Value": "storefront"},
]
PROGRAM_SERVERS = ("shop-web-legacy", "shop-web-2", "shop-web-collector")
DEAD = ("terminated", "shutting-down")


def _tagged(props, key: str, value: str) -> bool:
    return any(tag.get("Key") == key and tag.get("Value") == value
               for tag in (props.get("Tags") or []))


def _resources(snapshot, type_name: str) -> dict:
    return (snapshot.get("resources", {}) or {}).get(type_name, {}) or {}


def _shop_vpc_ids(snapshot) -> set:
    return {(props.get("VpcId") or identifier)
            for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items()
            if _tagged(props, "Name", VPC_NAME)}


def _shop_subnet_ids(snapshot) -> set:
    vpcs = _shop_vpc_ids(snapshot)
    return {(props.get("SubnetId") or identifier)
            for identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items()
            if props.get("VpcId") in vpcs}


def _lb_subnets(props) -> set:
    out = {s for s in (props.get("Subnets") or []) if s}
    for mapping in (props.get("SubnetMappings") or []):
        if mapping.get("SubnetId"):
            out.add(mapping["SubnetId"])
    return out


def _segment_placed(snapshot) -> bool:
    return any(_tagged(props, "Name", SEGMENT_NAME)
               for props in _resources(snapshot, "AWS::EC2::Subnet").values())


def _agent_in_the_network(snapshot) -> bool:
    """Something the agent stood up sits in the storefront's network."""
    vpcs = _shop_vpc_ids(snapshot)
    subnets = _shop_subnet_ids(snapshot)
    for props in _resources(snapshot, "AWS::EC2::SecurityGroup").values():
        if props.get("VpcId") in vpcs and props.get("GroupName") != "default":
            return True
    for props in _resources(snapshot, "AWS::EC2::Instance").values():
        if props.get("SubnetId") in subnets and not any(
                _tagged(props, "Name", name) for name in PROGRAM_SERVERS):
            return True
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        if props.get("VpcId") in vpcs:
            return True
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::LoadBalancer").values():
        if _lb_subnets(props) & subnets:
            return True
    return False


def _front_tier_without_the_placement(snapshot) -> bool:
    if not _shop_vpc_ids(snapshot) or _segment_placed(snapshot):
        return False
    return _agent_in_the_network(snapshot)


@distract(
    role="network engineer",
    responsibility="owns placement: which zone or segment each workload lands in",
    intent="the storefront's front tier spans a third segment of its network — a /24 in a third zone carrying the storefront's attribution and the front marking — and what fronts the storefront's traffic sits across all of them",
    api=on_api("ec2", "DescribeSubnets", phase="before"),
    release="after_completed",
    predicate=_front_tier_without_the_placement,
    resolution="The segments a service sits in are the ones the account puts it in by the time you are done, not the ones that answered earlier.",
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
    if not vpcs:
        return {"placed": None, "reason": f"no VPC tagged Name={VPC_NAME}", "fingerprint": []}
    vpc_id = vpcs[0]["VpcId"]
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]

    subnets = ec2.describe_subnets(Filters=in_vpc)["Subnets"]
    placed = [s for s in subnets
              if any(t.get("Key") == "Name" and t.get("Value") == SEGMENT_NAME
                     for t in (s.get("Tags") or []))]
    if placed:
        # Already placed by an earlier firing: make sure it still carries the marking.
        ec2.create_tags(Resources=[placed[0]["SubnetId"]], Tags=SEGMENT_TAGS)
        return {"placed": placed[0]["SubnetId"], "range": placed[0].get("CidrBlock"),
                "reason": "already placed", "fingerprint": [SEGMENT_NAME, SEGMENT_CIDR],
                "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}

    taken = {s.get("AvailabilityZone") for s in subnets}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    free = next((z for z in zones if z not in taken), None)
    if free is None:
        raise RuntimeError(f"no zone of {VPC_NAME} is free for the front tier's third segment")

    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=SEGMENT_CIDR, AvailabilityZone=free,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": SEGMENT_TAGS}],
    )["Subnet"]
    return {"placed": subnet["SubnetId"], "range": SEGMENT_CIDR, "zone": free,
            "fingerprint": [SEGMENT_NAME, SEGMENT_CIDR],
            "trigger": os.environ.get("CLOUDGYM_TRIGGER_KIND")}


if __name__ == "__main__":
    print(json.dumps(run()))
