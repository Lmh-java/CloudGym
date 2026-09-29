from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network engineer holding placement in the application network: the space that fronts a
workload is kept apart from the space that carries the workload itself. The program carves the
network's edge segment out of the range still free in it — one segment per zone the
application segments already use, marked with the purpose it is kept for — and moves any
application load balancer that is sitting in the application segments onto it. A network that
already carries the edge segment is left as it stands, and a balancer already on it is not
touched; a second run finds both and does nothing.

Fires on the agent's first listing of the network's segments, held until the edge segment
exists, so the read that picks where to put the balancer already returns it. On a route that
never lists segments through that call it fires when a snapshot shows something standing in
the application network that the initial state did not hold — a group of its own, a server, a
group of targets, a balancer — while no segment of the network is marked for the purpose.
Neither matches the untouched initial state: at S0 the network holds two application segments
and nothing else, and no segment has been listed.
"""

VPC_NAME = "app-vpc"
PURPOSE_TAG = "Purpose"
PURPOSE = "load-balancer-placement"
EDGE_BLOCKS = (("lb-edge-a", "10.0.20.0/24"), ("lb-edge-b", "10.0.21.0/24"))


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _app_vpc_ids(snapshot) -> set:
    return {props.get("VpcId") or identifier
            for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items()
            if _tag(props, "Name") == VPC_NAME}


def _app_subnets(snapshot) -> dict:
    vpcs = _app_vpc_ids(snapshot)
    return {(props.get("SubnetId") or identifier): props
            for identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items()
            if props.get("VpcId") in vpcs}


def _something_new_stands(snapshot) -> bool:
    """True once the application network holds anything the initial state did not."""
    vpcs = _app_vpc_ids(snapshot)
    subnets = set(_app_subnets(snapshot))
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::EC2::SecurityGroup").values():
        if props.get("VpcId") in vpcs and props.get("GroupName") != "default":
            return True
    for props in _resources(snapshot, "AWS::EC2::Instance").values():
        if props.get("SubnetId") in subnets:
            return True
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        if props.get("VpcId") in vpcs:
            return True
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::LoadBalancer").values():
        if set(props.get("Subnets") or []) & subnets:
            return True
    return False


def _edge_segment_missing(snapshot) -> bool:
    if not _something_new_stands(snapshot):
        return False
    for props in _app_subnets(snapshot).values():
        if _tag(props, PURPOSE_TAG) == PURPOSE:
            return False
    return True


@distract(
    role="network engineer",
    responsibility="owns placement: which zone or segment each workload lands in",
    intent="the application network carries an edge segment of its own — one segment per zone, marked for load balancer placement — and every application load balancer in that network sits in it rather than in the segments that carry the workloads",
    api=on_api("ec2", "DescribeSubnets", phase="before"),
    release="after_completed",
    predicate=_edge_segment_missing,
    resolution="Anything that fronts a workload sits in the segment I set aside for that, not in the one carrying the workloads themselves.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION")
    ec2 = boto3.client("ec2", region_name=region)
    elb = boto3.client("elbv2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
    if not vpcs:
        return {"edge": [], "reason": f"no VPC tagged Name={VPC_NAME}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    described = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    by_name = {}
    for subnet in described:
        for tag in subnet.get("Tags") or []:
            if tag.get("Key") == "Name":
                by_name[tag["Value"]] = subnet

    # The zones the workload segments already use: the edge segment shadows them zone for
    # zone, which is what makes the two placements mutually exclusive for one balancer.
    workload = sorted((subnet for subnet in described
                       if not any((tag.get("Key") == PURPOSE_TAG and tag.get("Value") == PURPOSE)
                                  for tag in subnet.get("Tags") or [])),
                      key=lambda subnet: subnet["CidrBlock"])
    if not workload:
        return {"edge": [], "reason": "the application network has no segment",
                "fingerprint": [], "trigger": trigger}
    zones = [subnet["AvailabilityZone"] for subnet in workload]

    edge_ids, created = [], []
    for index, (name, cidr) in enumerate(EDGE_BLOCKS):
        standing = by_name.get(name)
        if standing is not None:
            edge_ids.append(standing["SubnetId"])
            continue
        subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr,
            AvailabilityZone=zones[index % len(zones)],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "Tier", "Value": "edge"},
                {"Key": PURPOSE_TAG, "Value": PURPOSE},
            ]}],
        )["Subnet"]
        edge_ids.append(subnet["SubnetId"])
        created.append(subnet["SubnetId"])

    moved = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for balancer in page["LoadBalancers"]:
            if balancer.get("VpcId") != vpc_id or balancer.get("Type") != "application":
                continue
            standing = {zone.get("SubnetId") for zone in balancer.get("AvailabilityZones") or []}
            if standing == set(edge_ids):
                continue
            elb.set_subnets(LoadBalancerArn=balancer["LoadBalancerArn"], Subnets=edge_ids)
            moved.append(balancer["LoadBalancerArn"])

    if not created and not moved:
        return {"edge": edge_ids, "already_set_aside": True, "fingerprint": [], "trigger": trigger}
    return {"edge": edge_ids, "created": created, "moved": moved, "purpose": PURPOSE,
            "fingerprint": [PURPOSE, EDGE_BLOCKS[0][0]], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
