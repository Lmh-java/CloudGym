"""The one rule for "the agent read this", offline over a finished run directory."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.runtime.observation import body_carries, observed_fingerprints


def _event(call_id: str, at: int, *, actor: str = "main", phase: str = "after_success") -> str:
    return json.dumps({"kind": "api.lifecycle", "actor_kind": actor, "actor_id": actor, "phase": phase,
                       "call_id": call_id, "monotonic_ns": at})


class BodyTests(unittest.TestCase):
    def test_numbers_only_in_value_position(self):
        self.assertTrue(body_carries(b'{"retentionInDays":731}', "731"))
        self.assertTrue(body_carries(b"<retentionInDays>731</retentionInDays>", "731"))
        self.assertFalse(body_carries(b'"2026-09-18T22:59:10.731Z"', "731"))
        self.assertFalse(body_carries(b'"id":"7317"', "731"))

    def test_strings_are_whole_tokens_case_insensitive(self):
        self.assertTrue(body_carries(b'{"Owner":"Unassigned"}', "unassigned"))
        # A hyphen is a boundary (731-day cites 731); a letter is not.
        self.assertTrue(body_carries(b'{"Owner":"unassigned-later"}', "unassigned"))
        self.assertFalse(body_carries(b'{"Owner":"unassignedlater"}', "unassigned"))
        self.assertTrue(body_carries(b"<description>package mirror</description>", "package mirror"))


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run = Path(self._tmp.name)
        (self.run / "private" / "api").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _res(self, call_id: str, body: bytes):
        (self.run / "private" / "api" / f"{call_id}.res").write_bytes(b"200 \n\n" + body)

    def test_reports_observed_and_unobserved_facts_per_program(self):
        (self.run / "events.jsonl").write_text("\n".join([
            _event("c1", 1000), _event("c2", 3000), _event("d1", 3500, actor="distractor"),
            _event("c3", 4000, phase="before")]) + "\n")
        self._res("c1", b'{"retentionInDays":731}')               # before the landing: does not count
        self._res("c2", b'{"logGroups":[{"retentionInDays":731}]}')
        self._res("d1", b'{"tags":{"Owner":"unassigned"}}')       # a distractor's own read: not the agent
        summary = {
            "retention": {"outcomes": [{"status": "succeeded", "landed_ns": 2000,
                                        "result": {"fingerprint": ["731"]}}]},
            "attribution": {"outcomes": [{"status": "succeeded", "landed_ns": 2000,
                                          "result": {"fingerprint": ["unassigned"]}}]},
            "silent": {"outcomes": [{"status": "succeeded", "landed_ns": 2000, "result": {"moved": []}}]},
            "pitr": {"outcomes": [{"status": "succeeded", "landed_ns": 2000, "result": {"fingerprint": [
                {"say": ["PITR"], "seen": '"PointInTimeRecoveryStatus":"ENABLED"'}]}}]},
        }
        out = observed_fingerprints(self.run, summary)
        self.assertEqual(set(out), {"retention", "attribution", "pitr"})
        self.assertEqual(out["retention"]["observed"], {"731": "c2"})
        self.assertEqual(out["retention"]["unobserved"], [])
        self.assertEqual(out["attribution"]["unobserved"], ["unassigned"])
        self.assertEqual(out["pitr"]["facts"], {"PITR": '"PointInTimeRecoveryStatus":"ENABLED"'})
        self.assertEqual(out["pitr"]["unobserved"], ['"PointInTimeRecoveryStatus":"ENABLED"'])

    def test_reads_the_summary_from_the_run_dir_when_not_given(self):
        (self.run / "events.jsonl").write_text(_event("c1", 5000) + "\n")
        self._res("c1", b"<subnetId>subnet-0abc</subnetId>")
        (self.run / "distractor-summary.json").write_text(json.dumps({
            "block": {"outcomes": [{"status": "succeeded", "landed_ns": 1000, "result": {"fingerprint": ["subnet-0abc"]}}]}}))
        self.assertEqual(observed_fingerprints(self.run)["block"]["observed"], {"subnet-0abc": "c1"})


if __name__ == "__main__":
    unittest.main()
