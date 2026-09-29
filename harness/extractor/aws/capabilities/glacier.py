"""Capability adapter for ``aws_glacier_vault``.

Added 2026-09-22 (6 IaC-Eval rows touch it). S3 Glacier vaults have no CloudFormation
type, so the vault is read natively: ``glacier:ListVaults`` / ``DescribeVault`` for the
document, with the access policy, notification configuration and tags folded in from
their own calls (each may legitimately be absent). Needs ``glacier:*`` in the sandbox
SCP. A vault must be empty to delete; fixtures never upload an archive.
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


class GlacierVaultAdapter(CapabilityAdapter):
    terraform_type = "aws_glacier_vault"
    cloudcontrol_type = "AWS::Glacier::Vault"    # no CloudFormation type; the label the harness uses
    semantic_properties = (
        "AccessPolicy",
        "Notifications",
        "Tags",
        "VaultName",
    )
    volatile_fields = ("VaultARN", "CreationDate", "LastInventoryDate", "NumberOfArchives", "SizeInBytes")
    readiness_properties = ("VaultName", "VaultARN")

    def _client(self, session, region: str):
        return session.client("glacier", region_name=region)

    def _document(self, glacier, vault: dict) -> dict:
        from botocore.exceptions import ClientError

        name = vault["VaultName"]
        doc = _jsonable(dict(vault))
        doc.pop("ResponseMetadata", None)
        try:
            doc["AccessPolicy"] = glacier.get_vault_access_policy(vaultName=name)["policy"]["Policy"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        try:
            notifications = glacier.get_vault_notifications(vaultName=name)["vaultNotificationConfig"]
            doc["Notifications"] = _jsonable(notifications)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        tags = glacier.list_tags_for_vault(vaultName=name).get("Tags") or {}
        doc["Tags"] = [{"Key": k, "Value": v} for k, v in sorted(tags.items())]
        return doc

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        glacier = self._client(session, region)
        out: list[tuple[str, dict]] = []
        for page in glacier.get_paginator("list_vaults").paginate():
            for vault in page.get("VaultList", []):
                out.append((vault["VaultName"], self._document(glacier, vault)))
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        from botocore.exceptions import ClientError

        glacier = self._client(session, region)
        try:
            vault = glacier.describe_vault(vaultName=identifier)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return None
            raise
        return self._document(glacier, vault)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        session.client("glacier").add_tags_to_vault(vaultName=identifier, Tags={"cloudgym-smoke": "mutation-visible"})
        tags = [t for t in (properties.get("Tags") or []) if t.get("Key") != "cloudgym-smoke"]
        return {"Tags": sorted(tags + [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}], key=lambda t: t["Key"])}
