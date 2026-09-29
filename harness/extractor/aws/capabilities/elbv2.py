"""Capability adapters for Elastic Load Balancing v2: load balancer, target group,
listener, listener rule, and the target-group attachment projection.

Opened 2026-09-08 (SCP allowlists ``elasticloadbalancing:*``). Identifiers are
ARNs, which are also Terraform's ids. Listeners list per load balancer and
rules per listener (ResourceModel), like ``AWS::Lambda::Permission`` per
function. ``aws_lb_target_group_attachment`` is a projection: registered
targets are the target group document's ``Targets`` list. Classic ELB
(``aws_elb``) has no Cloud Control type and is deliberately not adapted; the
``aws_alb*`` aliases are not registered because no dataset row uses them.
"""

from .base import CapabilityAdapter


def _elb_tags(session, arn: str, existing: list | None) -> list[dict]:
    tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
    session.client("elbv2").add_tags(ResourceArns=[arn], Tags=tags)
    return [t for t in (existing or []) if t.get("Key") != "cloudgym-smoke"] + tags


class LoadBalancerAdapter(CapabilityAdapter):
    terraform_type = "aws_lb"
    cloudcontrol_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    semantic_properties = (
        "IpAddressType",
        "LoadBalancerAttributes",
        "Name",
        "Scheme",
        "SecurityGroups",   # rewritten to logical addresses during normalization
        "SubnetMappings",
        "Subnets",          # rewritten to logical addresses during normalization
        "Tags",
        "Type",
    )
    volatile_fields = ("LoadBalancerArn", "DNSName", "CanonicalHostedZoneID",
                       "LoadBalancerFullName", "LoadBalancerName")
    readiness_properties = ("LoadBalancerArn", "DNSName", "Type")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        return {"Tags": _elb_tags(session, identifier, properties.get("Tags"))}



class TargetGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_lb_target_group"
    cloudcontrol_type = "AWS::ElasticLoadBalancingV2::TargetGroup"
    semantic_properties = (
        "HealthCheckEnabled",
        "HealthCheckIntervalSeconds",
        "HealthCheckPath",
        "HealthCheckPort",
        "HealthCheckProtocol",
        "HealthCheckTimeoutSeconds",
        "HealthyThresholdCount",
        "IpAddressType",
        "Matcher",
        "Name",
        "Port",
        "Protocol",
        "ProtocolVersion",
        "Tags",
        "TargetGroupAttributes",
        "TargetType",
        "Targets",
        "UnhealthyThresholdCount",
        "VpcId",  # rewritten to a logical address during normalization
    )
    volatile_fields = ("TargetGroupArn", "TargetGroupFullName", "TargetGroupName",
                       "LoadBalancerArns")
    readiness_properties = ("TargetGroupArn", "TargetType")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        return {"Tags": _elb_tags(session, identifier, properties.get("Tags"))}



class TargetGroupAttachmentAdapter(TargetGroupAdapter):
    terraform_type = "aws_lb_target_group_attachment"
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        arn = attributes.get("target_group_arn")
        if not arn or not isinstance(arn, str):
            raise ValueError(f"{self.terraform_type}: state instance has no target_group_arn")
        return arn



class ListenerAdapter(CapabilityAdapter):
    terraform_type = "aws_lb_listener"
    cloudcontrol_type = "AWS::ElasticLoadBalancingV2::Listener"
    list_parent = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    semantic_properties = (
        "AlpnPolicy",
        "Certificates",
        "DefaultActions",
        "LoadBalancerArn",  # rewritten to a logical address during normalization
        "MutualAuthentication",
        "Port",
        "Protocol",
        "SslPolicy",
    )
    volatile_fields = ("ListenerArn",)
    readiness_properties = ("ListenerArn", "LoadBalancerArn", "DefaultActions")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"LoadBalancerArn": parent_properties["LoadBalancerArn"]}

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        # Once the load balancer is deleted, the handler may report the parent rather
        # than the listener as missing; a listener cannot outlive its load balancer.
        return "LoadBalancerNotFound" in str(error)



class ListenerRuleAdapter(CapabilityAdapter):
    terraform_type = "aws_lb_listener_rule"
    cloudcontrol_type = "AWS::ElasticLoadBalancingV2::ListenerRule"
    list_parent = "AWS::ElasticLoadBalancingV2::Listener"
    semantic_properties = (
        "Actions",
        "Conditions",
        "ListenerArn",  # rewritten to a logical address during normalization
        "Priority",
    )
    volatile_fields = ("RuleArn", "IsDefault")
    readiness_properties = ("RuleArn", "Priority")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"ListenerArn": parent_properties["ListenerArn"]}

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        return "ListenerNotFound" in str(error) or "LoadBalancerNotFound" in str(error)

