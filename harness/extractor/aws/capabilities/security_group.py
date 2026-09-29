"""Capability adapters for ``aws_security_group`` and its rule sub-resources.

The rule resources (``aws_vpc_security_group_ingress_rule``,
``aws_vpc_security_group_egress_rule``, legacy ``aws_security_group_rule``)
are projections of the group: Cloud Control folds every rule into the
group document's ``SecurityGroupIngress`` / ``SecurityGroupEgress`` lists, so
an out-of-band rule change is visible on the group. What the group document
does NOT carry is the per-rule identity (``sgr-…`` ids, per-rule tags); an
oracle that needs those would need the standalone
``AWS::EC2::SecurityGroupIngress`` type, which also lists fine.
"""

from .base import CapabilityAdapter


class SecurityGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_security_group"
    cloudcontrol_type = "AWS::EC2::SecurityGroup"
    semantic_properties = (
        "GroupName",
        "GroupDescription",
        "VpcId",  # rewritten to a logical address during normalization
        "SecurityGroupIngress",
        "SecurityGroupEgress",
        "Tags",
    )
    volatile_fields = ("GroupId", "Id", "OwnerId")
    readiness_properties = ("GroupId", "GroupName")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier], Tags=tags)
        return {"Tags": tags}


class _SecurityGroupRuleProjection(SecurityGroupAdapter):
    standalone = False

    def identifier_from_state(self, attributes: dict) -> str:
        group = attributes.get("security_group_id")
        if not group or not isinstance(group, str):
            raise ValueError(f"{self.terraform_type}: state instance has no security_group_id")
        return group


class SecurityGroupIngressRuleAdapter(_SecurityGroupRuleProjection):
    terraform_type = "aws_vpc_security_group_ingress_rule"


class SecurityGroupEgressRuleAdapter(_SecurityGroupRuleProjection):
    terraform_type = "aws_vpc_security_group_egress_rule"


class SecurityGroupRuleAdapter(_SecurityGroupRuleProjection):
    terraform_type = "aws_security_group_rule"
