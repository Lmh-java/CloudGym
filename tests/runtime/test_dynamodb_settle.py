"""Teardown waits for a DynamoDB table's indexes to settle before DeleteTable."""

from __future__ import annotations

import unittest

from harness.runtime.case import _dynamodb_settled


class _Client:
    def __init__(self, sequence):
        self.sequence = list(sequence)
        self.calls = 0

    def describe_table(self, TableName):
        self.calls += 1
        item = self.sequence.pop(0) if len(self.sequence) > 1 else self.sequence[0]
        if item == "missing":
            raise RuntimeError("ResourceNotFoundException: not found")
        table_status, index_status = item
        return {"Table": {"TableStatus": table_status,
                          "GlobalSecondaryIndexes": [{"IndexStatus": index_status}] if index_status else []}}


class SettleTests(unittest.TestCase):
    def test_waits_for_index_then_returns(self) -> None:
        client = _Client([("ACTIVE", "CREATING"), ("ACTIVE", "CREATING"), ("ACTIVE", "ACTIVE")])
        self.assertTrue(_dynamodb_settled(client, "t", timeout_s=10, poll_s=0))
        self.assertEqual(client.calls, 3)

    def test_updating_table_then_active(self) -> None:
        client = _Client([("UPDATING", None), ("ACTIVE", None)])
        self.assertTrue(_dynamodb_settled(client, "t", timeout_s=10, poll_s=0))

    def test_missing_table_is_settled(self) -> None:
        self.assertTrue(_dynamodb_settled(_Client(["missing"]), "t", timeout_s=10, poll_s=0))

    def test_timeout_returns_false(self) -> None:
        client = _Client([("ACTIVE", "CREATING")])
        self.assertFalse(_dynamodb_settled(client, "t", timeout_s=0, poll_s=0))
