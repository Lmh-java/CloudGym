"""Capability adapters for VPC DHCP option sets and their VPC association.

Added 2026-09-22 (7 IaC-Eval rows, ec2 already allowlisted). ``AWS::EC2::DHCPOptions`` is
read through Cloud Control (identifier = the ``dopt-`` id, also Terraform's id). The
association has a Cloud Control type (``AWS::EC2::VPCDHCPOptionsAssociation``, identifier
``<dopt id>|<vpc id>``) but its handler cannot be listed region-wide, so it is read natively
from ``ec2:DescribeVpcs``: every VPC carries exactly one option set (the account's default
one when nothing else is associated), and the envelope records that pair.
"""

from .base import CapabilityAdapter


class DhcpOptionsAdapter(CapabilityAdapter):
    terraform_type = "aws_vpc_dhcp_options"
    cloudcontrol_type = "AWS::EC2::DHCPOptions"
    semantic_properties = (
        "DomainName",
        "DomainNameServers",
        "Ipv6AddressPreferredLeaseTime",
        "NetbiosNameServers",
        "NetbiosNodeType",
        "NtpServers",
        "Tags",
    )
    volatile_fields = ("DhcpOptionsId",)
    readiness_properties = ("DhcpOptionsId",)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier], Tags=tags)
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}


class DhcpOptionsAssociationAdapter(CapabilityAdapter):
    terraform_type = "aws_vpc_dhcp_options_association"
    cloudcontrol_type = "AWS::EC2::VPCDHCPOptionsAssociation"
    semantic_properties = (
        "DhcpOptionsId",   # rewritten to a logical address during normalization
        "VpcId",           # rewritten to a logical address during normalization
    )
    volatile_fields = ()
    readiness_properties = ("DhcpOptionsId", "VpcId")

    def identifier_from_state(self, attributes: dict) -> str:
        dopt, vpc = attributes.get("dhcp_options_id"), attributes.get("vpc_id")
        if not dopt or not vpc:
            raise ValueError(f"{self.terraform_type}: state instance lacks dhcp_options_id / vpc_id")
        return f"{dopt}|{vpc}"

    def _client(self, session, region: str):
        return session.client("ec2", region_name=region)

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        for page in self._client(session, region).get_paginator("describe_vpcs").paginate():
            for vpc in page.get("Vpcs", []):
                dopt = vpc.get("DhcpOptionsId")
                if dopt:
                    out.append((f"{dopt}|{vpc['VpcId']}", {"DhcpOptionsId": dopt, "VpcId": vpc["VpcId"]}))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        dopt, _, vpc = identifier.partition("|")
        try:
            vpcs = self._client(session, region).describe_vpcs(VpcIds=[vpc]).get("Vpcs", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                return None
            raise
        if not vpcs or vpcs[0].get("DhcpOptionsId") != dopt:
            return None      # the VPC is gone or now carries another option set
        return {"DhcpOptionsId": dopt, "VpcId": vpc}
