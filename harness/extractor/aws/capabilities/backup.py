"""Capability adapters for AWS Backup: vault, plan, selection.

Cloud Control facts (verified live 2026-09-08): all three list region-wide.
Identifiers: vault = ``BackupVaultName``, plan = ``BackupPlanId`` (both equal
Terraform's id); selection = ``<BackupPlanId>_<SelectionId>`` while Terraform's
id is the bare selection id with the plan in ``plan_id``.

Vaults and plans are free; only recovery points bill storage. Fixtures
schedule rules far in the future so no backup job ever runs.
"""

from .base import CapabilityAdapter


def _tag_map(session, arn: str) -> dict:
    tags = {"cloudgym-smoke": "mutation-visible"}
    session.client("backup").tag_resource(ResourceArn=arn, Tags=tags)
    return tags


class BackupVaultAdapter(CapabilityAdapter):
    terraform_type = "aws_backup_vault"
    cloudcontrol_type = "AWS::Backup::BackupVault"
    semantic_properties = (
        "AccessPolicy",
        "BackupVaultName",
        "BackupVaultTags",
        "EncryptionKeyArn",
        "LockConfiguration",
        "Notifications",
    )
    volatile_fields = ("BackupVaultArn",)
    readiness_properties = ("BackupVaultName", "BackupVaultArn")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        arn = properties.get("BackupVaultArn")
        return {"BackupVaultTags": _tag_map(session, arn)} if arn else None


class BackupPlanAdapter(CapabilityAdapter):
    terraform_type = "aws_backup_plan"
    cloudcontrol_type = "AWS::Backup::BackupPlan"
    semantic_properties = ("BackupPlan", "BackupPlanTags")
    volatile_fields = ("BackupPlanArn", "BackupPlanId", "VersionId")
    readiness_properties = ("BackupPlanId", "BackupPlanArn", "BackupPlan")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        arn = properties.get("BackupPlanArn")
        return {"BackupPlanTags": _tag_map(session, arn)} if arn else None


class BackupSelectionAdapter(CapabilityAdapter):
    terraform_type = "aws_backup_selection"
    cloudcontrol_type = "AWS::Backup::BackupSelection"
    semantic_properties = (
        "BackupPlanId",  # rewritten to a logical address during normalization
        "BackupSelection",
    )
    volatile_fields = ("Id", "SelectionId")
    readiness_properties = ("Id", "SelectionId", "BackupPlanId")

    def identifier_from_state(self, attributes: dict) -> str:
        plan_id = attributes.get("plan_id")
        selection_id = attributes.get("id")
        if not plan_id or not selection_id:
            raise ValueError(f"{self.terraform_type}: state instance needs plan_id and id")
        # Cloud Control's Id is ``<selection id>_<plan id>`` (live smoke 2026-09-23: the reverse
        # order reads as a missing plan).
        return f"{selection_id}_{plan_id}"
    # A selection is immutable (every property is create-only): no smoke_mutation.
