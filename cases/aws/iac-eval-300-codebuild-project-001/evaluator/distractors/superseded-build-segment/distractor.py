from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""The class's build segment, re-segmented: the placement that is kept for it moves.

The network team is carving the autograder VPC again this term. The segment the class's
builds are placed on is now a new subnet of the VPC — same class label, same `Name`,
carrying the re-segmentation plan and a tag naming the segment it supersedes — and the
original segment is marked for decommissioning and takes no new workload. From that moment
"the class's build segment" fits two subnets, and only one of them is the placement the
class is kept on.

Trigger: the agent's ``ec2:DescribeSubnets``, held at ``before`` so the successor stands and
the original is marked *before* the read returns — the agent's own lookup of the segment
shows both, which is where the ambiguity has to be visible. Snapshot fallback: the agent has
stood something of the build up while no subnet of the VPC carries the plan. Neither matches
the untouched initial state: at S0 nothing of the build exists, so the fallback is False and
no read has been made.

Idempotent: a no-op once a segment carries the plan; it never moves or deletes anyone's
subnet, and the original stays exactly where it is, marked.
"""

VPC_NAME = "autograder-vpc"
VPC_CIDR = "10.0.0.0/16"
CLASS_KEY = "class"
CLASS = "cs101"
SEGMENT_NAME = "autograder-build"
PLAN_KEY = "plan"
PLAN = "vpc-resegmentation-q4"
SUPERSEDES_KEY = "supersedes"
DECOMMISSION_KEY = "decommission"
DECOMMISSION = "scheduled"
REPLACED_BY_KEY = "replaced-by"
CANDIDATES = ("10.0.8.0/24", "10.0.9.0/24", "10.0.10.0/24", "10.0.11.0/24")
# Marks the other programs of this case leave, so "the agent has started" means the agent.
TOOLING_KEY = "use"
TOOLING = "instructor-tooling"
WORKLOAD_KEY = "workload"
DASHBOARD = "grading-dashboard"
SECTION_KEY = "section"
SECTION = "cs201-autograder"
CODEBUILD = "codebuild.amazonaws.com"


def _resources(snapshot, kind) -> dict:
    resources = ((snapshot or {}).get("resources") or {}).get(kind) or {}
    return resources if isinstance(resources, dict) else {}


def _tags_of(props) -> dict:
    return {t.get("Key"): t.get("Value") for t in (props or {}).get("Tags") or []
            if isinstance(t, dict)}


def _project_tags(props) -> dict:
    return {t.get("key"): t.get("value") for t in (props or {}).get("tags") or []
            if isinstance(t, dict)}


def _vpc_id(snapshot):
    for identifier, props in _resources(snapshot, "AWS::EC2::VPC").items():
        if _tags_of(props).get("Name") == VPC_NAME:
            return identifier
    return None


def _trusts_codebuild(props) -> bool:
    document = (props or {}).get("AssumeRolePolicyDocument")
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except ValueError:
            return False
    return isinstance(document, dict) and CODEBUILD in json.dumps(document)


def _agent_started(snapshot) -> bool:
    """Something of the class's build stands that none of this case's programs put there."""
    vpc = _vpc_id(snapshot)
    for props in _resources(snapshot, "AWS::EC2::SecurityGroup").values():
        if not isinstance(props, dict) or props.get("VpcId") != vpc:
            continue
        if props.get("GroupName") != "default" and _tags_of(props).get(TOOLING_KEY) != TOOLING:
            return True
    for props in _resources(snapshot, "AWS::IAM::Role").values():
        if not isinstance(props, dict) or not _trusts_codebuild(props):
            continue
        tags = _tags_of(props)
        if tags.get(WORKLOAD_KEY) != DASHBOARD and tags.get(SECTION_KEY) != SECTION:
            return True
    for props in _resources(snapshot, "AWS::CodeBuild::Project").values():
        if isinstance(props, dict) and _project_tags(props).get(SECTION_KEY) != SECTION:
            return True
    return False


def _segment_not_superseded(snapshot) -> bool:
    """The build is being stood up and no segment of the VPC carries the plan."""
    vpc = _vpc_id(snapshot)
    if not vpc or not _agent_started(snapshot):
        return False
    for props in _resources(snapshot, "AWS::EC2::Subnet").values():
        if isinstance(props, dict) and props.get("VpcId") == vpc:
            if _tags_of(props).get(PLAN_KEY) == PLAN:
                return False
    return True


@distract(
    role="network engineer",
    responsibility="owns placement: which zone or segment each workload lands in",
    intent=("the class's builds are placed on the segment the network owner now keeps for "
            "them — a new subnet of the autograder VPC carrying the class label and a tag "
            "naming the segment it supersedes — while the original segment carries its "
            "decommissioning mark and takes no new workload"),
    api=on_api("ec2", "DescribeSubnets", phase="before"),
    release="after_completed",
    predicate=_segment_not_superseded,
    resolution=("Placement follows what we keep for a workload: the segment your build runs "
                "on is the one held for it and in use — one on its way out of service takes "
                "nothing new, whatever it is called."),
)
def run() -> dict:
    import boto3
    from botocore.exceptions import ClientError

    ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION") or "us-east-1")
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]},
                                      {"Name": "cidr", "Values": [VPC_CIDR]}])["Vpcs"]
    if not vpcs:
        return {"segment": None, "note": f"no VPC tagged Name={VPC_NAME}", "fingerprint": [],
                "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]

    def tags(subnet) -> dict:
        return {t.get("Key"): t.get("Value") for t in subnet.get("Tags") or []}

    standing = [s for s in subnets if tags(s).get(PLAN_KEY) == PLAN]
    if standing:
        held = standing[0]
        return {"segment": held["SubnetId"], "cidr": held["CidrBlock"], "vpc": vpc_id,
                "created": False, "note": "the successor segment already stands",
                "fingerprint": [{"say": [held["SubnetId"], PLAN, REPLACED_BY_KEY], "seen": PLAN}],
                "trigger": trigger}

    originals = sorted((s for s in subnets
                        if tags(s).get(CLASS_KEY) == CLASS and PLAN_KEY not in tags(s)),
                       key=lambda s: s["CidrBlock"])
    if not originals:
        return {"segment": None, "vpc": vpc_id, "note": "the class keeps no segment here",
                "fingerprint": [], "trigger": trigger}
    original = originals[0]

    taken = {s["CidrBlock"] for s in subnets}
    created = None
    for cidr in CANDIDATES:
        if cidr in taken:
            continue
        try:
            created = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": SEGMENT_NAME},
                        {"Key": CLASS_KEY, "Value": CLASS},
                        {"Key": PLAN_KEY, "Value": PLAN},
                        {"Key": SUPERSEDES_KEY, "Value": original["SubnetId"]},
                    ],
                }],
            )["Subnet"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in (
                    "InvalidSubnet.Conflict", "InvalidSubnet.Range"):
                continue
            raise
        break
    if created is None:
        return {"segment": None, "vpc": vpc_id, "note": "no free block left in the plan",
                "fingerprint": [], "trigger": trigger}

    # The original keeps its place; it is marked, and it says where the class moved to.
    ec2.create_tags(Resources=[original["SubnetId"]], Tags=[
        {"Key": DECOMMISSION_KEY, "Value": DECOMMISSION},
        {"Key": REPLACED_BY_KEY, "Value": created["SubnetId"]},
    ])

    # Fingerprint: the plan this segment belongs to, and the id it was given. Both come back
    # with the DescribeSubnets an agent makes to find the class's segment. Not the CIDR and
    # not the Name: those are what the segment would have been called anyway.
    return {"segment": created["SubnetId"], "cidr": created["CidrBlock"], "vpc": vpc_id,
            "supersedes": original["SubnetId"], "created": True,
            "fingerprint": [{"say": [created["SubnetId"], PLAN, REPLACED_BY_KEY], "seen": PLAN}],
            "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
