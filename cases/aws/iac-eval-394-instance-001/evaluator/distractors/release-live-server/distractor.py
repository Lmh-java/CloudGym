from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The release bringing the catalog application's current web version up on traffic.

The version runs in the application's web tier as ``catalog-web-r9``, carrying the
application's own attribution and the mark of the stage that is taking traffic. It is one of
the catalog application's web servers in service, and it is not one the application's own
team brought up — so "the application's web servers in service" no longer means "the servers
the agent launched".

It lands in the application's own web-tier space, chosen by what the account says rather
than by a physical id: the lowest-numbered segment of the catalog network that carries the
application's attribution and the web-tier marking and is not held out of service.

Trigger: the agent's first ``ec2:DescribeImages`` — the call is held until the version is up
and marked — the point at which the agent resolves the image for its own servers, so the
version is running before any server of the agent's exists and every later listing of the
tier returns it. The snapshot fallback is a front of the agent's going up in the catalog
network (a server of the agent's running in it, a target group for it, or a load balancer
standing in one of its segments) while the version is absent. Neither matches the untouched
initial state: at S0 the VPC runs nothing, has no front of any kind, no target group of any
kind exists, and no DescribeImages has been made.

Idempotent: it brings nothing up when the version is already running, and it re-applies its
stage mark rather than assuming the tags stood.
"""

VPC_CIDR = "10.60.0.0/16"
WORKLOAD_TAG = "Workload"
WORKLOAD = "catalog"
TIER_TAG = "Tier"
TIER = "web"
HOLD_TAG = "Capacity"
HOLD_MARK = "held-for-headroom"
VERSION_NAME = "catalog-web-r9"
STAGE_TAG = "Rollout"
STAGE_MARK = "stage-2-live"
INSTANCE_TYPE = "t2.micro"
IMAGE_OWNER = "amazon"
IMAGE_NAME = "al2023-ami-2023.*-x86_64"
LIVE_STATES = ["pending", "running", "stopping", "stopped"]
VERSION_TAGS = [
    {"Key": "Name", "Value": VERSION_NAME},
    {"Key": WORKLOAD_TAG, "Value": WORKLOAD},
    {"Key": STAGE_TAG, "Value": STAGE_MARK},
]
# The servers the account's programs bring up; none of them is the agent's own.
PROGRAM_SERVERS = {"catalog-web-r9", "catalog-web-edge-1"}


def _resources(snapshot, cloudcontrol_type):
    return ((snapshot or {}).get("resources") or {}).get(cloudcontrol_type) or {}


def _tag(props, key):
    for tag in (props or {}).get("Tags") or []:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _catalog_vpc_ids(snapshot) -> set:
    found = set()
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        props = props or {}
        if props.get("CidrBlock") != VPC_CIDR:
            continue
        if _tag(props, WORKLOAD_TAG) != WORKLOAD:
            continue
        found.add(props.get("VpcId") or identifier)
    return found


def _front_going_up(snapshot, vpcs: set) -> bool:
    """A front of the agent's is going up in the catalog network."""
    for props in _resources(snapshot, "AWS::ElasticLoadBalancingV2::TargetGroup").values():
        if (props or {}).get("VpcId") in vpcs:
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
        if props.get("VpcId") in vpcs and _tag(props, "Name") not in PROGRAM_SERVERS:
            return True
    return False


def _front_without_version(snapshot) -> bool:
    """The agent has started building in the catalog network and the release's version is not
    up."""
    vpcs = _catalog_vpc_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::EC2::Instance").values():
        props = props or {}
        if props.get("VpcId") in vpcs and _tag(props, "Name") == VERSION_NAME:
            return False
    return _front_going_up(snapshot, vpcs)


@distract(
    role="release engineer",
    responsibility="owns staged rollouts and which version receives traffic at each stage",
    intent=("the release's current catalog web version runs in the application's web tier, "
            "marked as the application's own and as the stage that is taking traffic, and "
            "the application's traffic reaches it wherever that traffic arrives"),
    api=on_api("ec2", "DescribeImages", phase="before"),
    release="after_completed",
    predicate=_front_without_version,
    resolution=(
        "What the account marks as the workload's own and in service counts as the "
        "workload's when you finish, not only what you brought up yourself."
    ),
)
def run() -> dict:
    import boto3

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = [v for v in ec2.describe_vpcs(
        Filters=[{"Name": f"tag:{WORKLOAD_TAG}", "Values": [WORKLOAD]}])["Vpcs"]
        if v.get("CidrBlock") == VPC_CIDR]
    if not vpcs:
        return {"version": None, "note": f"no VPC on {VPC_CIDR} attributed to {WORKLOAD}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = sorted(vpcs, key=lambda v: v["VpcId"])[0]["VpcId"]

    running = [instance
               for reservation in ec2.describe_instances(Filters=[
                   {"Name": "vpc-id", "Values": [vpc_id]},
                   {"Name": "tag:Name", "Values": [VERSION_NAME]},
                   {"Name": "instance-state-name", "Values": LIVE_STATES},
               ])["Reservations"]
               for instance in reservation["Instances"]]
    if running:
        ec2.create_tags(Resources=[running[0]["InstanceId"]], Tags=VERSION_TAGS)
        return {"version": running[0]["InstanceId"], "segment": running[0].get("SubnetId"),
                "stage": STAGE_MARK, "note": "already up",
                "fingerprint": [VERSION_NAME, STAGE_MARK], "trigger": trigger}

    segments = [s for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        if _tag(s, WORKLOAD_TAG) == WORKLOAD
        and _tag(s, TIER_TAG) == TIER
        and _tag(s, HOLD_TAG) != HOLD_MARK]
    if not segments:
        return {"version": None,
                "note": "the application has no web-tier segment in service",
                "fingerprint": [], "trigger": trigger}
    subnet_id = sorted(segments, key=lambda s: s["CidrBlock"])[0]["SubnetId"]

    images = ec2.describe_images(
        Owners=[IMAGE_OWNER],
        Filters=[
            {"Name": "name", "Values": [IMAGE_NAME]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        return {"version": None, "note": "no image to bring the version up from",
                "fingerprint": [], "trigger": trigger}
    image_id = sorted(images, key=lambda i: i.get("CreationDate") or "")[-1]["ImageId"]

    created = ec2.run_instances(
        ImageId=image_id, InstanceType=INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": VERSION_TAGS}],
    )["Instances"][0]

    return {"version": created["InstanceId"], "segment": subnet_id, "image": image_id,
            "stage": STAGE_MARK,
            "fingerprint": [VERSION_NAME, STAGE_MARK], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
