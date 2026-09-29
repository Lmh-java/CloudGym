"""Capability adapter for ``aws_dynamodb_table_item``.

Added 2026-09-23 (row 166; dynamodb already allowlisted). An item has no Cloud Control type,
so it is read natively: every table in the region is scanned (bounded; sandbox tables are
small) and each item becomes one envelope, identified by ``<table>|<key as DynamoDB JSON>``
(key attributes only, keys sorted). Terraform's own id format is not relied on: the binding
rebuilds the same identifier from ``table_name``, ``hash_key``, ``range_key`` and ``item``.
"""

import json

from .base import CapabilityAdapter

SCAN_LIMIT = 2000   # items per table; a larger table is not a sandbox fixture


def item_identifier(table: str, key: dict) -> str:
    return f"{table}|{json.dumps(key, sort_keys=True, separators=(',', ':'))}"


class DynamoDbTableItemAdapter(CapabilityAdapter):
    terraform_type = "aws_dynamodb_table_item"
    cloudcontrol_type = "AWS::DynamoDB::TableItem"      # no such Cloud Control type: native only
    semantic_properties = ("Item", "TableName")
    volatile_fields = ()
    readiness_properties = ("Item", "TableName")

    def identifier_from_state(self, attributes: dict) -> str:
        table, hash_key, range_key = attributes.get("table_name"), attributes.get("hash_key"), attributes.get("range_key")
        raw = attributes.get("item")
        if not table or not hash_key or not raw:
            raise ValueError(f"{self.terraform_type}: state instance lacks table_name / hash_key / item")
        item = json.loads(raw) if isinstance(raw, str) else raw
        key = {k: item[k] for k in (hash_key, range_key) if k and k in item}
        return item_identifier(table, key)

    def _client(self, session, region: str):
        return session.client("dynamodb", region_name=region)

    def native_describe(self, session, region: str) -> list[tuple[str, dict]]:
        ddb = self._client(session, region)
        out: list[tuple[str, dict]] = []
        for page in ddb.get_paginator("list_tables").paginate():
            for table in page.get("TableNames", []):
                try:
                    schema = ddb.describe_table(TableName=table)["Table"]["KeySchema"]
                except ddb.exceptions.ResourceNotFoundException:
                    continue
                key_names = [k["AttributeName"] for k in schema]
                seen = 0
                for scan in ddb.get_paginator("scan").paginate(TableName=table, ConsistentRead=True):
                    for item in scan.get("Items", []):
                        key = {k: item[k] for k in key_names if k in item}
                        out.append((item_identifier(table, key), {"TableName": table, "Item": item}))
                        seen += 1
                    if seen >= SCAN_LIMIT:
                        break
        return out

    def native_read(self, session, region: str, identifier: str) -> dict | None:
        table, _, key_json = identifier.partition("|")
        ddb = self._client(session, region)
        try:
            item = ddb.get_item(TableName=table, Key=json.loads(key_json), ConsistentRead=True).get("Item")
        except ddb.exceptions.ResourceNotFoundException:
            return None
        return {"TableName": table, "Item": item} if item else None

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        table, _, key_json = identifier.partition("|")
        session.client("dynamodb").update_item(
            TableName=table, Key=json.loads(key_json),
            UpdateExpression="SET cloudgym_smoke = :v", ExpressionAttributeValues={":v": {"S": "mutation-visible"}})
        item = dict(properties.get("Item") or {})
        item["cloudgym_smoke"] = {"S": "mutation-visible"}
        return {"Item": item}
