"""Capability adapter for ``aws_vpc_peering_connection``.

Added 2026-09-23 (rows 452-454, ec2 already allowlisted). Read natively from
``ec2:DescribeVpcPeeringConnections``: Cloud Control's ``AWS::EC2::VPCPeeringConnection``
carries only the two VPC ids, the peer owner/region and tags, not the connection's status
(``pending-acceptance`` / ``provisioning`` / ``active`` / ``rejected`` / ``deleted``) nor the
peering options, and status is what an execution conflict on a peering turns on. A deleted or
rejected connection stays describable for a while; it counts as absent.
"""

from .base import CapabilityAdapter

_GONE = ("deleted", "rejected", "failed", "expired")


class VpcPeeringConnectionAdapter(CapabilityAdapter):
    terraform_type = "aws_vpc_peering_connection"
    cloudcontrol_type = "AWS::EC2::VPCPeeringConnection"
    semantic_properties = ("AccepterVpcInfo", "RequesterVpcInfo", "Status", "Tags")
    volatile_fields = ("VpcPeeringConnectionId", "ExpirationTime")
    readiness_properties = ("VpcPeeringConnectionId", "Status")

    def _client(self, session, region: str):
        return session.client("ec2", region_name=region)

    @staticmethod
    def _plain(pcx: dict) -> dict:
        out = dict(pcx)
        if out.get("ExpirationTime") is not None:
            out["ExpirationTime"] = str(out["ExpirationTime"])
        return out

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        out: list[tuple[str, dict]] = []
        for page in self._client(session, region).get_paginator("describe_vpc_peering_connections").paginate():
            for pcx in page.get("VpcPeeringConnections", []):
                if (pcx.get("Status") or {}).get("Code") in _GONE:
                    continue
                out.append((pcx["VpcPeeringConnectionId"], self._plain(pcx)))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        try:
            found = self._client(session, region).describe_vpc_peering_connections(
                VpcPeeringConnectionIds=[identifier]).get("VpcPeeringConnections", [])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidVpcPeeringConnectionID.NotFound":
                return None
            raise
        if not found or (found[0].get("Status") or {}).get("Code") in _GONE:
            return None
        return self._plain(found[0])

    def project(self, properties: dict) -> dict:
        projected = super().project(properties)
        # Status: the code is the state; the message restates it in prose.
        if isinstance(projected.get("Status"), dict):
            projected["Status"] = {"Code": projected["Status"].get("Code")}
        return projected

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier], Tags=tags)
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}
