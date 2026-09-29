from __future__ import annotations

import json
import os

from harness.runtime import distract, on_api

"""Network security engineer holding what may ever reach a load balancer in the application
network: one group, kept by the account for that and marked for it, admits web traffic and
admits it only from inside the network's own range. Every balancer there is reached through
that group and through nothing else. The program creates the group where the network does not
have it, and takes away any rule admitting the whole internet from a group a balancer in the
network is already carrying. It creates nothing else and never detaches a group; a network that
already has the group, with no balancer open to the internet, is left exactly as it stands.

Fires on the agent's first listing of the network's groups, held until the group exists, so
the read that picks what the balancer carries already returns it. On a route that never lists
groups through that call it fires when a snapshot shows something standing in the application
network that the initial state did not hold — a group of its own, a server, a group of targets,
a balancer — while the network has no group kept for reaching balancers. Neither matches the
untouched initial state: at S0 the network holds only the group the VPC brings with it, runs
nothing and carries no balancer, and no group has been listed.
"""

VPC_NAME = "app-vpc"
ENTRY_GROUP = "vpc-edge-ingress"
ENTRY_DESCRIPTION = "account shared ingress for load balancers in the application network"
NETWORK_RANGE = "10.0.0.0/16"
WEB_PORT = 80
ENTRY_TAGS = [
    {"Key": "Name", "Value": ENTRY_GROUP},
    {"Key": "Purpose", "Value": "load-balancer-ingress"},
]


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


def _app_subnet_ids(snapshot) -> set:
    vpcs = _app_vpc_ids(snapshot)
    return {props.get("SubnetId") or identifier
            for identifier, props in _resources(snapshot, "AWS::EC2::Subnet").items()
            if props.get("VpcId") in vpcs}


def _something_new_stands(snapshot) -> bool:
    vpcs = _app_vpc_ids(snapshot)
    subnets = _app_subnet_ids(snapshot)
    if not vpcs:
        return False
    for props in _resources(snapshot, "AWS::EC2::SecurityGroup").values():
        if props.get("VpcId") in vpcs and props.get("GroupName") not in ("default", ENTRY_GROUP):
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


def _no_kept_group(snapshot) -> bool:
    if not _something_new_stands(snapshot):
        return False
    vpcs = _app_vpc_ids(snapshot)
    for props in _resources(snapshot, "AWS::EC2::SecurityGroup").values():
        if props.get("VpcId") in vpcs and props.get("GroupName") == ENTRY_GROUP:
            return False
    return True


@distract(
    role="network security engineer",
    responsibility="owns ingress exposure: what may ever be reachable, from where",
    intent="the application network keeps one group for reaching a load balancer, admitting the web port only from the network's own range, and every load balancer there is reached through that group and nothing wider",
    api=on_api("ec2", "DescribeSecurityGroups", phase="before"),
    release="after_completed",
    predicate=_no_kept_group,
    resolution="Reaching a Load Balancer here goes through the group I provide for it; a workload does not front one with a group of its own.",
)
def run() -> dict:
    import boto3

    region = os.environ.get("AWS_REGION")
    ec2 = boto3.client("ec2", region_name=region)
    elb = boto3.client("elbv2", region_name=region)
    trigger = os.environ.get("CLOUDGYM_TRIGGER_KIND")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [VPC_NAME]}])["Vpcs"]
    if not vpcs:
        return {"kept": None, "reason": f"no VPC tagged Name={VPC_NAME}",
                "fingerprint": [], "trigger": trigger}
    vpc_id = vpcs[0]["VpcId"]

    standing = ec2.describe_security_groups(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "group-name", "Values": [ENTRY_GROUP]},
    ])["SecurityGroups"]
    if standing:
        group_id, created = standing[0]["GroupId"], False
    else:
        group_id = ec2.create_security_group(
            GroupName=ENTRY_GROUP, Description=ENTRY_DESCRIPTION, VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": ENTRY_TAGS}],
        )["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": WEB_PORT, "ToPort": WEB_PORT,
            "IpRanges": [{"CidrIp": NETWORK_RANGE, "Description": ENTRY_DESCRIPTION}],
        }])
        created = True

    # Nothing in this network is reachable from the whole internet: a balancer already
    # carrying a group that says otherwise loses that rule.
    carried = set()
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for balancer in page["LoadBalancers"]:
            if balancer.get("VpcId") == vpc_id and balancer.get("Type") == "application":
                carried |= set(balancer.get("SecurityGroups") or [])
    closed = []
    for identifier in sorted(carried):
        described = ec2.describe_security_groups(GroupIds=[identifier])["SecurityGroups"]
        for group in described:
            open_rules = [
                {k: v for k, v in rule.items() if k != "UserIdGroupPairs"}
                for rule in group.get("IpPermissions") or []
                if any(entry.get("CidrIp") == "0.0.0.0/0" for entry in rule.get("IpRanges") or [])
            ]
            if not open_rules:
                continue
            ec2.revoke_security_group_ingress(GroupId=identifier, IpPermissions=open_rules)
            closed.append(identifier)

    if not created and not closed:
        return {"kept": group_id, "already_kept": True, "fingerprint": [], "trigger": trigger}
    return {"kept": group_id, "name": ENTRY_GROUP, "created": created, "closed": closed,
            "fingerprint": [ENTRY_GROUP], "trigger": trigger}


if __name__ == "__main__":
    print(json.dumps(run()))
