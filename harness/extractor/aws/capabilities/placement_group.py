"""Capability adapter for ``aws_placement_group``.

Added 2026-09-23 (rows 131 and 192, ec2 already allowlisted). Read through Cloud Control
(``AWS::EC2::PlacementGroup``), identified by the group name, which is also Terraform's
id. Membership lives on the instances (``Placement.GroupName`` in the instance adapter's
document), not on the group. Cluster groups admit only some instance types; whether the
sandbox's t3 classes launch into one is what the smoke of rows 131/192 must show.
"""

from .base import CapabilityAdapter


class PlacementGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_placement_group"
    cloudcontrol_type = "AWS::EC2::PlacementGroup"
    semantic_properties = ("GroupName", "PartitionCount", "SpreadLevel", "Strategy", "Tags")
    volatile_fields = ()
    readiness_properties = ("GroupName", "Strategy")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        ec2 = session.client("ec2")
        group = ec2.describe_placement_groups(GroupNames=[identifier])["PlacementGroups"][0]
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        ec2.create_tags(Resources=[group["GroupId"]], Tags=tags)
        return {"Tags": [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"] + tags}
