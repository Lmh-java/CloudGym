"""Capability adapters for EFS: ``aws_efs_file_system``, ``aws_efs_mount_target`` and
``aws_efs_file_system_policy``.

Added 2026-09-23 (rows 130, 191, 423, 425). Needs ``elasticfilesystem:*`` in the sandbox SCP;
an idle file system is billed per GB stored, so an empty one costs nothing (left out of
``BILLABLE_TYPES``). Cloud Control reads the file system by id (Terraform's id); mount
targets are listed per file system; the resource policy is a projection of the file system's
``FileSystemPolicy``. Lifecycle states (creating / available / updating / deleting) are not in
Cloud Control's read: the refusal catalogue observes them natively.
"""

from .base import CapabilityAdapter


class EfsFileSystemAdapter(CapabilityAdapter):
    terraform_type = "aws_efs_file_system"
    cloudcontrol_type = "AWS::EFS::FileSystem"
    semantic_properties = (
        "AvailabilityZoneName",
        "BackupPolicy",
        "Encrypted",
        "FileSystemPolicy",
        "FileSystemProtection",
        "FileSystemTags",
        "KmsKeyId",
        "LifecyclePolicies",
        "PerformanceMode",
        "ProvisionedThroughputInMibps",
        "ThroughputMode",
    )
    volatile_fields = ("Arn", "FileSystemId")
    readiness_properties = ("FileSystemId", "PerformanceMode")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("efs").tag_resource(ResourceId=identifier, Tags=tags)
        return {"FileSystemTags": [t for t in (properties.get("FileSystemTags") or [])
                                   if t.get("Key") != "cloudgym-smoke"] + tags}


class EfsFileSystemPolicyAdapter(CapabilityAdapter):
    terraform_type = "aws_efs_file_system_policy"
    cloudcontrol_type = "AWS::EFS::FileSystem"
    standalone = False
    semantic_properties = ("FileSystemPolicy",)
    readiness_properties = ("FileSystemId",)


class EfsMountTargetAdapter(CapabilityAdapter):
    terraform_type = "aws_efs_mount_target"
    cloudcontrol_type = "AWS::EFS::MountTarget"
    list_parent = "AWS::EFS::FileSystem"
    semantic_properties = ("FileSystemId", "IpAddress", "SecurityGroups", "SubnetId")
    volatile_fields = ("Id",)
    readiness_properties = ("Id", "FileSystemId", "SubnetId")

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"FileSystemId": parent_properties["FileSystemId"]}

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        import time

        efs = session.client("efs")
        for _ in range(40):                     # security groups change only when available
            state = efs.describe_mount_targets(MountTargetId=identifier)["MountTargets"][0]["LifeCycleState"]
            if state == "available":
                break
            time.sleep(5)
        groups = list(properties.get("SecurityGroups") or [])
        if len(groups) < 2:        # the fixture declares two groups; dropping one is the change
            return None
        efs.modify_mount_target_security_groups(MountTargetId=identifier, SecurityGroups=groups[:1])
        return {"SecurityGroups": groups[:1]}
