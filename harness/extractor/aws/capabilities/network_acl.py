"""Capability adapters for ``aws_network_acl`` and ``aws_default_network_acl``.

Added 2026-09-23 (rows 237, 455, 456, 457; ec2 already allowlisted). Cloud Control splits
a network ACL into three types (``AWS::EC2::NetworkAcl`` with only VpcId and Tags,
``NetworkAclEntry`` per rule, ``SubnetNetworkAclAssociation`` per subnet), while Terraform
declares the rules and subnets inline, and those are what a conflict changes. So the ACL
is read natively from ``ec2:DescribeNetworkAcls``: one envelope per ACL carrying its
entries and associations verbatim. Every VPC has a default ACL; the default adapter binds
the same envelopes through ``aws_default_network_acl``'s id.

The projection sorts entries by (egress, rule number) and reduces each association to its
subnet: association ids are regenerated whenever a subnet moves between ACLs and say
nothing about the state.
"""

from .base import CapabilityAdapter


class NetworkAclAdapter(CapabilityAdapter):
    terraform_type = "aws_network_acl"
    cloudcontrol_type = "AWS::EC2::NetworkAcl"
    semantic_properties = ("Associations", "Entries", "IsDefault", "Tags", "VpcId")
    volatile_fields = ("NetworkAclId", "OwnerId")
    readiness_properties = ("NetworkAclId", "VpcId")

    def _client(self, session, region: str):
        return session.client("ec2", region_name=region)

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        for page in self._client(session, region).get_paginator("describe_network_acls").paginate():
            for acl in page.get("NetworkAcls", []):
                out.append((acl["NetworkAclId"], acl))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        try:
            acls = self._client(session, region).describe_network_acls(NetworkAclIds=[identifier]).get("NetworkAcls", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidNetworkAclID.NotFound":
                return None
            raise
        return acls[0] if acls else None

    def project(self, properties: dict) -> dict:
        projected = super().project(properties)
        if isinstance(projected.get("Entries"), list):
            projected["Entries"] = sorted(projected["Entries"],
                                          key=lambda e: (bool(e.get("Egress")), int(e.get("RuleNumber") or 0)))
        if isinstance(projected.get("Associations"), list):
            projected["Associations"] = sorted(({"SubnetId": a.get("SubnetId")} for a in projected["Associations"]),
                                               key=lambda a: str(a["SubnetId"]))
        return projected

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        ec2 = session.client("ec2")
        ec2.create_network_acl_entry(NetworkAclId=identifier, RuleNumber=4242, Protocol="6", RuleAction="deny",
                                     Egress=False, CidrBlock="192.0.2.0/24", PortRange={"From": 4242, "To": 4242})
        acl = self.native_read(session, ec2.meta.region_name, identifier) or {}
        return {"Entries": self.project(acl).get("Entries")}


class DefaultNetworkAclAdapter(NetworkAclAdapter):
    terraform_type = "aws_default_network_acl"
