"""The refusal catalogue: SDK-derived entries, manual entries marked, and the wait helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from botocore.exceptions import ClientError

from harness.runtime import refusals
from harness.runtime.refusals import Observation, build, entry, load, observe_state, wait_for_state, wait_until_busy


class CatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = build()
        cls.entries = {e["id"]: e for e in cls.doc["entries"]}

    def test_committed_catalogue_matches_the_installed_sdk(self) -> None:
        committed = json.loads(refusals.CATALOGUE_PATH.read_text())
        self.assertEqual(committed, json.loads(json.dumps(self.doc)), "run `uv run refusals build` and commit seeds/refusals.json")

    def test_sdk_entries_carry_the_waiter_read_and_declared_operations(self) -> None:
        rds = self.entries["rds.db-instance"]
        self.assertEqual(rds["source"], "sdk")
        obs = rds["observe"][0]
        self.assertEqual((obs["operation"], obs["identifier_param"], obs["path"], obs["settled"], obs["waiter"]),
                         ("DescribeDBInstances", "DBInstanceIdentifier", "DBInstances[].DBInstanceStatus",
                          "available", "DBInstanceAvailable"))
        self.assertIn("deleting", obs["terminal"])
        for op in ("ModifyDBInstance", "CreateDBSnapshot", "CreateDBInstanceReadReplica", "RebootDBInstance"):
            self.assertIn(op, rds["refusals"]["InvalidDBInstanceStateFault"])
        lam = self.entries["lambda.function"]
        self.assertEqual([o["path"] for o in lam["observe"]], ["State", "LastUpdateStatus"])
        self.assertIn("UpdateFunctionConfiguration", lam["refusals"]["ResourceConflictException"])
        self.assertIn("ChangeResourceRecordSets", self.entries["route53.change"]["refusals"]["PriorRequestNotComplete"])
        self.assertEqual(self.entries["dynamodb.table"]["observe"][0]["absent_error"], "ResourceNotFoundException")

    def test_manual_entries_are_marked_and_cited(self) -> None:
        for name in ("autoscaling.group", "sqs.queue", "ec2.instance"):
            self.assertEqual(self.entries[name]["source"], "manual", name)
            self.assertTrue(self.entries[name]["citation"].startswith("https://"), name)
        self.assertEqual(self.entries["sqs.queue"]["observe"], [])
        self.assertEqual(self.entries["sqs.queue"]["window_s"], 60)
        # the SDK still supplies what it has: Auto Scaling's error shapes are declared there
        self.assertIn("StartInstanceRefresh", self.entries["autoscaling.group"]["refusals"]["InstanceRefreshInProgressFault"])

    def test_unknown_shape_fails_the_build(self) -> None:
        import botocore.session

        with self.assertRaises(ValueError):
            refusals._declaring_operations(botocore.session.get_session(), "rds", "NoSuchFault")


class _Rds:
    def __init__(self, states):
        self.states = list(states)
        self.calls = 0

    def describe_db_instances(self, **kwargs):
        assert kwargs == {"DBInstanceIdentifier": "primary"}
        self.calls += 1
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        if state == "GONE":
            raise ClientError({"Error": {"Code": "DBInstanceNotFound", "Message": "x"}}, "DescribeDBInstances")
        return {"DBInstances": [{"DBInstanceIdentifier": "primary", "DBInstanceStatus": state}]}


class _Session:
    def __init__(self, client):
        self._client = client

    def client(self, name, region_name=None):
        return self._client


class WaitTests(unittest.TestCase):
    def test_observe_state_wraps_list_identifiers(self) -> None:
        class _Elb:
            def describe_load_balancers(self, **kwargs):
                assert kwargs == {"LoadBalancerArns": ["arn:lb"]}
                return {"LoadBalancers": [{"State": {"Code": "provisioning"}}]}

        obs = Observation("DescribeLoadBalancers", "LoadBalancerArns", "LoadBalancers[].State.Code", "active")
        self.assertEqual(observe_state(_Elb(), obs, "arn:lb", service="elbv2"), "provisioning")

    def test_wait_until_busy_returns_on_first_non_settled_state(self) -> None:
        rds = _Rds(["available", "available", "modifying"])
        result = wait_until_busy(_Session(rds), "rds.db-instance", "primary", timeout_s=30, poll_s=0.0)
        self.assertTrue(result["fired"])
        self.assertEqual((result["state"], result["observations"]), ("modifying", 3))

    def test_wait_times_out_without_raising_and_stops_on_terminal(self) -> None:
        rds = _Rds(["available"])
        result = wait_for_state(_Session(rds), "rds.db-instance", "primary",
                                until=lambda s: s == "modifying", timeout_s=0.0, poll_s=0.0)
        self.assertEqual((result["fired"], result["state"]), (False, "available"))
        rds = _Rds(["modifying", "failed"])
        result = wait_for_state(_Session(rds), "rds.db-instance", "primary",
                                until=lambda s: s == "available", timeout_s=30, poll_s=0.0)
        self.assertEqual((result["fired"], result["state"]), (False, "failed"))

    def test_settled_treats_a_missing_resource_as_settled(self) -> None:
        from harness.runtime.refusals import wait_until_settled

        class _Ddb:
            def describe_table(self, **kwargs):
                raise ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": "x"}}, "DescribeTable")

        result = wait_until_settled(_Session(_Ddb()), "dynamodb.table", "orders", timeout_s=5, poll_s=0.0)
        self.assertEqual((result["fired"], result["state"]), (True, None))

    def test_dynamodb_index_backfill_is_busy_while_the_table_reads_active(self) -> None:
        # The pilot's finding: TableStatus returns to ACTIVE while an index is still building.
        from harness.runtime.refusals import wait_until_settled

        class _Ddb:
            def __init__(self, index_states):
                self.index_states = list(index_states)

            def describe_table(self, **kwargs):
                state = self.index_states.pop(0) if len(self.index_states) > 1 else self.index_states[0]
                return {"Table": {"TableStatus": "ACTIVE", "GlobalSecondaryIndexes": [
                    {"IndexName": "Mine", "IndexStatus": "ACTIVE"}, {"IndexName": "Theirs", "IndexStatus": state}]}}

        busy = wait_until_busy(_Session(_Ddb(["CREATING"])), "dynamodb.table", "t", timeout_s=5, poll_s=0.0)
        self.assertEqual((busy["fired"], busy["state"], busy["states"]), (True, "1", ["ACTIVE", "1"]))
        # settled only once every index is ACTIVE (two describe calls per poll: one per observation)
        ddb = _Ddb(["CREATING", "CREATING", "CREATING", "CREATING", "ACTIVE"])
        settled = wait_until_settled(_Session(ddb), "dynamodb.table", "t", timeout_s=5, poll_s=0.0)
        self.assertEqual((settled["fired"], settled["states"], settled["observations"]), (True, ["ACTIVE", "0"], 3))
        entry_ = load()["dynamodb.table"]
        self.assertEqual((entry_.source, [o.source for o in entry_.observe]), ("sdk", ["sdk", "manual"]))

    def test_falsified_pairs_leave_the_refusing_operations(self) -> None:
        ddb = load()["dynamodb.table"]
        self.assertIn("UpdateTimeToLive", ddb.refusals["ResourceInUseException"])     # the SDK declares it
        self.assertNotIn("UpdateTimeToLive", ddb.refusing_operations())                # a real run falsified it
        self.assertIn("UpdateTable", ddb.refusing_operations())
        self.assertEqual(ddb.falsified()["UpdateTimeToLive"]["case"], "iac-eval-165-dynamodb-table-002")

    def test_entry_without_a_read_cannot_be_waited_on(self) -> None:
        with self.assertRaises(ValueError):
            wait_for_state(_Session(None), "sqs.queue", "q", until=lambda s: True, timeout_s=1)
        with self.assertRaises(KeyError):
            entry("nope")
        self.assertIn("ModifyDBInstance", load()["rds.db-instance"].refusing_operations())


if __name__ == "__main__":
    unittest.main()
