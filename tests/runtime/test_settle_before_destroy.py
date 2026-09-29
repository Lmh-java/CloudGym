"""Teardown waits for catalogued resources in the Terraform state to settle before destroying."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness.runtime.case import CaseHooks


class _Ddb:
    def __init__(self):
        self.calls = 0

    def describe_table(self, **kwargs):
        self.calls += 1
        # busy for the first two polls (one poll = two describe calls: table status, index count)
        status = "CREATING" if self.calls <= 4 else "ACTIVE"
        return {"Table": {"TableStatus": "ACTIVE", "GlobalSecondaryIndexes": [{"IndexStatus": status}]}}


class _Session:
    def __init__(self):
        self.ddb = _Ddb()

    def client(self, name, region_name=None):
        assert name == "dynamodb"
        return self.ddb


class SettleBeforeDestroyTests(unittest.TestCase):
    def test_waits_for_each_catalogued_resource_in_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "terraform.tfstate").write_text(json.dumps({"resources": [
                {"mode": "managed", "type": "aws_dynamodb_table",
                 "instances": [{"attributes": {"id": "orders", "name": "orders"}}]},
                {"mode": "managed", "type": "aws_s3_bucket", "instances": [{"attributes": {"id": "b"}}]},
                {"mode": "data", "type": "aws_dynamodb_table", "instances": [{"attributes": {"name": "ignored"}}]},
            ]}))
            hooks = CaseHooks.__new__(CaseHooks)
            hooks.workspace = SimpleNamespace(workdir=workdir)
            session = _Session()
            results = CaseHooks._settle_owned(hooks, session)
            self.assertEqual(list(results), ["aws_dynamodb_table/orders"])
            self.assertTrue(results["aws_dynamodb_table/orders"]["fired"])
            self.assertEqual(results["aws_dynamodb_table/orders"]["states"], ["ACTIVE", "0"])
            self.assertGreaterEqual(session.ddb.calls, 6)

    def test_no_state_means_nothing_to_settle(self) -> None:
        hooks = CaseHooks.__new__(CaseHooks)
        hooks.workspace = None
        self.assertEqual(CaseHooks._settle_owned(hooks, _Session()), {})


if __name__ == "__main__":
    unittest.main()
