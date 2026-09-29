"""Capability adapters for RDS: instance, subnet group, parameter group, option group,
manual snapshot.

Opened 2026-09-08: the SCP allowlists ``rds:*`` and caps ``CreateDBInstance`` at
db.t3/db.t4g micro+small, single-AZ (``OnlyCheapDatabaseClasses`` /
``NoMultiAzDatabases``). Cloud Control identifiers are the names; Terraform's
``aws_db_instance`` id is the DBI *resource* id (provider >= 5), so the adapter
binds on ``identifier``. Instances take 5-10 minutes to create and 3-5 to
delete; ``delete_resource`` skips the final snapshot.

Added 2026-09-22: ``aws_db_option_group`` (Cloud Control ``AWS::RDS::OptionGroup``, seconds
to create) and ``aws_db_snapshot``. A manual snapshot has no CloudFormation type, so it is
read natively from ``rds:DescribeDBSnapshots`` (the CodeBuild pattern) and is settled only
in the ``available`` status; while it is ``creating`` the source instance sits in
``backing-up`` and refuses modifications, which is the execution-conflict window the EC
cases use.
"""

from datetime import datetime

from .base import CapabilityAdapter


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _rds_tags(session, arn: str, existing: list | None) -> list[dict]:
    tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
    session.client("rds").add_tags_to_resource(ResourceName=arn, Tags=tags)
    return [t for t in (existing or []) if t.get("Key") != "cloudgym-smoke"] + tags


class DbInstanceAdapter(CapabilityAdapter):
    terraform_type = "aws_db_instance"
    cloudcontrol_type = "AWS::RDS::DBInstance"
    semantic_properties = (
        "AllocatedStorage",
        "AutoMinorVersionUpgrade",
        "BackupRetentionPeriod",
        "CopyTagsToSnapshot",
        "DBInstanceClass",
        "DBInstanceIdentifier",
        "DBName",
        "DBParameterGroupName",   # rewritten to a logical address during normalization
        "DBSubnetGroupName",      # rewritten to a logical address during normalization
        "DeletionProtection",
        "EnableCloudwatchLogsExports",
        "EnablePerformanceInsights",
        "Engine",
        "EngineVersion",
        "Iops",
        "KmsKeyId",
        "MasterUsername",
        "MaxAllocatedStorage",
        "MonitoringInterval",
        "MultiAZ",
        "Port",
        "PreferredBackupWindow",
        "PreferredMaintenanceWindow",
        "PubliclyAccessible",
        "StorageEncrypted",
        "StorageType",
        "Tags",
        "VPCSecurityGroups",      # rewritten to logical addresses during normalization
    )
    volatile_fields = ("DBInstanceArn", "DbiResourceId", "Endpoint", "CACertificateIdentifier",
                       "AvailabilityZone", "DBSystemId")
    readiness_properties = ("DBInstanceIdentifier", "DBInstanceArn", "DbiResourceId", "Endpoint")

    def identifier_from_state(self, attributes: dict) -> str:
        identifier = attributes.get("identifier")
        if not identifier or not isinstance(identifier, str):
            raise ValueError(f"{self.terraform_type}: state instance has no 'identifier'")
        return identifier

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        arn = properties.get("DBInstanceArn")
        return {"Tags": _rds_tags(session, arn, properties.get("Tags"))} if arn else None


class DbSubnetGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_db_subnet_group"
    cloudcontrol_type = "AWS::RDS::DBSubnetGroup"
    semantic_properties = (
        "DBSubnetGroupDescription",
        "DBSubnetGroupName",
        "SubnetIds",  # rewritten to logical addresses during normalization
        "Tags",
    )
    volatile_fields = ()
    readiness_properties = ("DBSubnetGroupName", "SubnetIds")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        rds = session.client("rds")
        arn = rds.describe_db_subnet_groups(DBSubnetGroupName=identifier)["DBSubnetGroups"][0]["DBSubnetGroupArn"]
        return {"Tags": _rds_tags(session, arn, properties.get("Tags"))}


class DbParameterGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_db_parameter_group"
    cloudcontrol_type = "AWS::RDS::DBParameterGroup"
    semantic_properties = (
        "DBParameterGroupName",
        "Description",
        "Family",
        "Parameters",
        "Tags",
    )
    volatile_fields = ()
    readiness_properties = ("DBParameterGroupName", "Family")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        rds = session.client("rds")
        arn = rds.describe_db_parameter_groups(DBParameterGroupName=identifier)["DBParameterGroups"][0]["DBParameterGroupArn"]
        return {"Tags": _rds_tags(session, arn, properties.get("Tags"))}


class DbOptionGroupAdapter(CapabilityAdapter):
    terraform_type = "aws_db_option_group"
    cloudcontrol_type = "AWS::RDS::OptionGroup"
    semantic_properties = (
        "EngineName",
        "MajorEngineVersion",
        "OptionConfigurations",
        "OptionGroupDescription",
        "OptionGroupName",
        "Tags",
    )
    volatile_fields = ()
    readiness_properties = ("OptionGroupName", "EngineName", "MajorEngineVersion")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        rds = session.client("rds")
        arn = rds.describe_option_groups(OptionGroupName=identifier)["OptionGroupsList"][0]["OptionGroupArn"]
        return {"Tags": _rds_tags(session, arn, properties.get("Tags"))}


class DbSnapshotAdapter(CapabilityAdapter):
    """``aws_db_snapshot``: a manual snapshot, read natively (no Cloud Control type)."""

    terraform_type = "aws_db_snapshot"
    cloudcontrol_type = "AWS::RDS::DBSnapshot"
    semantic_properties = (
        "AllocatedStorage",
        "DBInstanceIdentifier",   # rewritten to a logical address during normalization
        "DBSnapshotIdentifier",
        "Encrypted",
        "Engine",
        "EngineVersion",
        "KmsKeyId",
        "OptionGroupName",
        "Port",
        "SnapshotType",
        "StorageType",
        "TagList",
    )
    volatile_fields = ("DBSnapshotArn", "SnapshotCreateTime", "OriginalSnapshotCreateTime", "InstanceCreateTime",
                       "PercentProgress", "Status", "DbiResourceId", "AvailabilityZone", "VpcId")
    readiness_properties = ("DBSnapshotIdentifier", "DBSnapshotArn", "Status")

    def _client(self, session, region: str):
        return session.client("rds", region_name=region)

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        rds = self._client(session, region)
        out: list[tuple[str, dict]] = []
        for page in rds.get_paginator("describe_db_snapshots").paginate(SnapshotType="manual"):
            out.extend((s["DBSnapshotIdentifier"], _jsonable(s)) for s in page.get("DBSnapshots", []))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        try:
            got = self._client(session, region).describe_db_snapshots(DBSnapshotIdentifier=identifier)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBSnapshotNotFound":
                return None
            raise
        snapshots = got.get("DBSnapshots", [])
        return _jsonable(snapshots[0]) if snapshots else None

    def ready(self, properties: dict) -> bool:
        # A snapshot exists from the first describe but is settled only once available.
        return super().ready(properties) and properties.get("Status") == "available"

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        arn = properties.get("DBSnapshotArn")
        return {"TagList": _rds_tags(session, arn, properties.get("TagList"))} if arn else None
