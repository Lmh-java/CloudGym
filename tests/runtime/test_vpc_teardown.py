"""Unowned contents of a VPC are removed in dependency order; Terraform's own stay."""
from harness.runtime.vpc_teardown import clear_vpc_dependencies


class _Pages:
    def __init__(self, pages): self.pages = pages
    def paginate(self, **kw): return list(self.pages)


class _Ec2:
    def __init__(self, calls): self.calls = calls
    def describe_instances(self, Filters): return {"Reservations": [{"Instances": [{"InstanceId": "i-agent", "State": {"Name": "running"}}, {"InstanceId": "i-owned", "State": {"Name": "running"}}]}]}
    def terminate_instances(self, InstanceIds): self.calls.append(("terminate", tuple(InstanceIds)))
    def get_waiter(self, name):
        class W:
            def wait(self_inner, **kw): pass
        return W()
    def describe_vpc_endpoints(self, Filters): return {"VpcEndpoints": []}
    def describe_network_interfaces(self, Filters): return {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Status": "available"}]}
    def delete_network_interface(self, NetworkInterfaceId): self.calls.append(("delete_eni", NetworkInterfaceId))
    def describe_security_groups(self, Filters): return {"SecurityGroups": [
        {"GroupId": "sg-default", "GroupName": "default"},
        {"GroupId": "sg-owned", "GroupName": "owned", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "UserIdGroupPairs": [{"GroupId": "sg-agent"}]}]},
        {"GroupId": "sg-agent", "GroupName": "agent", "IpPermissionsEgress": [{"IpProtocol": "-1"}]}]}
    def revoke_security_group_ingress(self, GroupId, IpPermissions): self.calls.append(("revoke_in", GroupId))
    def revoke_security_group_egress(self, GroupId, IpPermissions): self.calls.append(("revoke_out", GroupId))
    def delete_security_group(self, GroupId): self.calls.append(("delete_sg", GroupId))
    def describe_subnets(self, Filters): return {"Subnets": [{"SubnetId": "subnet-owned"}, {"SubnetId": "subnet-agent"}]}
    def delete_subnet(self, SubnetId): self.calls.append(("delete_subnet", SubnetId))
    def describe_route_tables(self, Filters): return {"RouteTables": [
        {"RouteTableId": "rtb-main", "Associations": [{"Main": True}]},
        {"RouteTableId": "rtb-agent", "Associations": [{"RouteTableAssociationId": "rtbassoc-1"}]}]}
    def disassociate_route_table(self, AssociationId): self.calls.append(("disassociate", AssociationId))
    def delete_route_table(self, RouteTableId): self.calls.append(("delete_rtb", RouteTableId))
    def describe_internet_gateways(self, Filters): return {"InternetGateways": [{"InternetGatewayId": "igw-owned"}]}
    def detach_internet_gateway(self, **kw): self.calls.append(("detach_igw", kw["InternetGatewayId"]))
    def delete_internet_gateway(self, InternetGatewayId): self.calls.append(("delete_igw", InternetGatewayId))


class _Elbv2:
    def __init__(self, calls): self.calls = calls
    def get_paginator(self, name):
        if name == "describe_load_balancers":
            return _Pages([{"LoadBalancers": [{"LoadBalancerArn": "arn:lb-agent", "VpcId": "vpc-1"}, {"LoadBalancerArn": "arn:lb-other", "VpcId": "vpc-2"}]}])
        return _Pages([{"TargetGroups": [{"TargetGroupArn": "arn:tg-agent", "VpcId": "vpc-1"}]}])
    def modify_load_balancer_attributes(self, **kw): self.calls.append(("unprotect", kw["LoadBalancerArn"]))
    def delete_load_balancer(self, LoadBalancerArn): self.calls.append(("delete_lb", LoadBalancerArn))
    def get_waiter(self, name):
        class W:
            def wait(self_inner, **kw): pass
        return W()
    def delete_target_group(self, TargetGroupArn): self.calls.append(("delete_tg", TargetGroupArn))


class _Session:
    def __init__(self, calls): self.c = calls
    def client(self, name): return {"ec2": _Ec2(self.c), "elbv2": _Elbv2(self.c)}[name]


def test_unowned_resources_are_removed_and_owned_ones_kept():
    calls = []
    removed = clear_vpc_dependencies(_Session(calls), "vpc-1", owned={"i-owned", "sg-owned", "subnet-owned", "igw-owned", "vpc-1"})
    assert ("delete_lb", "arn:lb-agent") in calls and ("delete_lb", "arn:lb-other") not in calls
    assert ("terminate", ("i-agent",)) in calls
    assert ("delete_sg", "sg-agent") in calls and ("delete_sg", "sg-owned") not in calls
    assert ("revoke_in", "sg-owned") in calls          # the owned group's rule referenced the agent's group
    assert ("delete_subnet", "subnet-agent") in calls and ("delete_subnet", "subnet-owned") not in calls
    assert ("disassociate", "rtbassoc-1") in calls and ("delete_rtb", "rtb-agent") in calls and ("delete_rtb", "rtb-main") not in calls
    assert ("delete_igw", "igw-owned") not in calls
    assert "rtb/rtb-agent" in removed and "sg/sg-agent" in removed
