from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The one group the account runs for the imaging application's HTTP traffic.

The platform does not let a workload stand a target group of its own for traffic the account
already runs one for: there is a single group per workload and serving port, health-checked on
the path the account checks on and carrying the platform's reference, and nothing duplicates
it. A front that stands its own second group for the same traffic is the duplication this
exists to prevent, so the group the agent is asked to create and the single group the account
runs cannot both be what the imaging listener forwards to.

The group is stood in the imaging application's own network, found by what the account says
rather than by a physical id: the VPC on the application's range carrying its attribution.

Trigger: the agent's first ``elbv2:DescribeTargetGroups`` — the call is held until the group
stands — the call that asks what groups the account already runs, so the account's group and
the path it health-checks on come back in that very response, before any part of the front is
built. The snapshot fallback is a front of the agent's going up in the imaging network (a host
of the agent's running in it, a target group for it, or a load balancer standing in one of its
segments) while the account's group is absent. Neither matches the untouched initial state: at
S0 the VPC runs nothing, no target group of any kind exists, and no DescribeTargetGroups has
been made.

Idempotent: it stands nothing further once the account's group is there, and it re-applies the
health-check path, the reference and the attribution rather than assuming they stood.
"""

VPC_CIDR = "10.80.0.0/16"
APP_TAG = "Application"
APP = "imaging"
SHARED_GROUP = "shared-imaging-front"
PLATFORM_TAG = "Platform"
PLATFORM_REF = "PLT-6620"
HEALTH_PATH = "/status/ready"
SERVING_PORT = 80
GROUP_TAGS = [
    {"Key": "Name", "Value": SHARED_GROUP},
    {"Key": APP_TAG, "Value": APP},
    {"Key": PLATFORM_TAG, "Value": PLATFORM_REF},
]
# The hosts the account's programs bring up; none of them is the agent's own.
PROGRAM_HOSTS = {"imaging-serving-r7"}


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _imaging_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, APP_TAG) != APP:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _front_going_up(snapshot, vpcs: set) -> bool:
    """A front of the agent's is going up in the imaging network."""
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        props = props or {}
        if props.get("VpcId") in vpcs and props.get("Name") != SHARED_GROUP:
            return True
    segments = {
        (props or {}).get("SubnetId") or identifier
        for identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items()
        if (props or {}).get("VpcId") in vpcs
    }
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::LoadBalancer").values():
        if segments.intersection((props or {}).get("Subnets") or []):
            return True
    for props in _resources(snapshot, "AWS::EC2::Instance").values():
        props = props or {}
        if props.get("VpcId") in vpcs and _tag(props, "Name") not in PROGRAM_HOSTS:
            return True
    return False


def _front_without_shared_group(snapshot) -> bool:
    """The agent has started building in the imaging network and the account's group is not
    there."""
    vpcs = _imaging_vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        props = props or {}
        if props.get("VpcId") in vpcs and props.get("Name") == SHARED_GROUP:
            return False
    return _front_going_up(snapshot, vpcs)


@distract(
    role="platform engineer",
    responsibility="owns shared infrastructure that workloads reuse rather than duplicate",
    intent=("the account runs one target group for the imaging application's HTTP traffic — "
            "instance-type, on the serving port, in the application's own network, "
            "health-checked on the account's path and carrying the platform's reference — and "
            "nothing duplicates it"),
    api=on_api("elbv2", "DescribeTargetGroups", phase="before"),
    release="after_completed",
    predicate=_front_without_shared_group,
    resolution=(
        "There is already one the account keeps for that workload's traffic — use it as it "
        "stands instead of standing a second."
    ),
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION") or "us-east-1"
    ec2 = boto3.client("ec2", region_name=region)
    elb = boto3.client("elbv2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{APP_TAG}", "Values": [APP]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"group": None, "note": f"no VPC on {VPC_CIDR} attributed to {APP}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    standing = [group for page in elb.get_paginator("describe_target_groups").paginate()
                for group in page["TargetGroups"]
                if group.get("VpcId") == vpc_id and group.get("TargetGroupName") == SHARED_GROUP]
    if standing:
        arn = standing[0]["TargetGroupArn"]
        elb.modify_target_group(TargetGroupArn=arn, HealthCheckProtocol="HTTP",
                                HealthCheckPath=HEALTH_PATH)
        elb.add_tags(ResourceArns=[arn], Tags=GROUP_TAGS)
        return {"group": SHARED_GROUP, "group_arn": arn, "reference": PLATFORM_REF,
                "health_path": HEALTH_PATH, "note": "already standing",
                "fingerprint": [SHARED_GROUP, HEALTH_PATH], "trigger": trigger}

    created = elb.create_target_group(
        Name=SHARED_GROUP,
        Protocol="HTTP",
        Port=SERVING_PORT,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        HealthCheckPath=HEALTH_PATH,
        Tags=GROUP_TAGS,
    )["TargetGroups"][0]

    return {"group": SHARED_GROUP, "group_arn": created["TargetGroupArn"],
            "reference": PLATFORM_REF, "health_path": HEALTH_PATH,
            "fingerprint": [SHARED_GROUP, HEALTH_PATH], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
