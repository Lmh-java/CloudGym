"""Long-run hygiene: network blips are not verdicts or dirty accounts, a batch runs on one
commit, a norm whose program fails is loud, and orphaned query-logging configs are seen."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.bench.report import Row, summarize
from harness.bench.runner import code_changed
from harness.netcheck import is_transient_network_error, wait_for_network
from harness.runtime.distractors import stderr_tail


class NetworkTests(unittest.TestCase):
    def test_transient_shapes_are_recognised(self):
        for text in (
            'dial tcp: lookup route53.amazonaws.com: no such host',
            'botocore.exceptions.EndpointConnectionError: Could not connect to the endpoint URL: "https://portal.sso"',
            "Temporary failure in name resolution",
            "read tcp 10.0.0.2:5432: i/o timeout",
        ):
            self.assertTrue(is_transient_network_error(text), text)

    def test_refusals_and_real_errors_are_not_transient(self):
        for text in ("AccessDenied: not authorized", "InvalidParameterValue: Invalid security group description",
                     "terraform apply-initial exited 1: resource already exists", "", None):
            self.assertFalse(is_transient_network_error(text), repr(text))

    def test_wait_for_network_returns_when_the_probe_answers(self):
        answers = iter([False, False, True])
        slept: list[float] = []
        ok = wait_for_network(timeout_s=100, poll_s=5, probe=lambda: next(answers), sleep=slept.append)
        self.assertTrue(ok)
        self.assertEqual(slept, [5, 5])

    def test_wait_for_network_gives_up_at_the_deadline(self):
        import itertools
        clock = itertools.count(0, 10)
        import harness.netcheck as nc
        original = nc.time.monotonic
        nc.time.monotonic = lambda: next(clock)
        try:
            ok = wait_for_network(timeout_s=25, poll_s=1, probe=lambda: False, sleep=lambda _: None)
        finally:
            nc.time.monotonic = original
        self.assertFalse(ok)


class CodePinTests(unittest.TestCase):
    def test_dirty_or_moved_head_refuses(self):
        pinned = {"commit": "a" * 40, "dirty": False}
        self.assertIsNone(code_changed(pinned, {"commit": "a" * 40, "dirty": False}))
        self.assertIn("dirty", code_changed(pinned, {"commit": "a" * 40, "dirty": True}))
        self.assertIn("HEAD moved", code_changed(pinned, {"commit": "b" * 40, "dirty": False}))
        self.assertIsNone(code_changed(None, {"commit": "b" * 40, "dirty": True}))   # not pinned


class ProgramGateTests(unittest.TestCase):
    SUMMARY = {
        "ok": {"status": "succeeded", "outcomes": [{"status": "failed", "exit_code": 1, "stderr_tail": "boom"},
                                                   {"status": "succeeded", "exit_code": 0}]},
        "dead": {"status": "failed", "outcomes": [{"status": "failed", "exit_code": 1,
                                                   "stderr_tail": "InvalidParameterValue: description"}]},
        "quiet": {"status": "not-fired", "outcomes": []},
    }

    def test_stderr_tail_keeps_the_end(self):
        self.assertEqual(stderr_tail("short"), "short")
        long = "x" * 1000 + "Error: last line"
        tail = stderr_tail(long)
        self.assertTrue(tail.endswith("Error: last line") and tail.startswith("…") and len(tail) <= 801)


def _row(case, statuses, *, validity="valid", case_dir=None, distractors=True):
    fields = {f.name: None for f in Row.__dataclass_fields__.values()}
    fields.update(batch="b", arm="x", case=case, trial=1, run_id="r", agent="claude", model="m", awareness="none",
                  modality="cli", distractors=distractors, status="completed", verdict="pass", validity=validity,
                  distractor_status=json.dumps(statuses) if statuses else None, case_dir=case_dir, run_dir="/tmp/r")
    return Row(**fields)


class NormReportTests(unittest.TestCase):
    def test_program_that_never_succeeds_is_an_alert(self):
        rows = [_row("c", {"a": "succeeded", "b": "failed"}), _row("c", {"a": "succeeded", "b": "failed"})]
        text = summarize(rows)
        self.assertIn("## Norms", text)
        self.assertIn("c/b: program never succeeds", text)
        self.assertNotIn("c/a:", text)

    def test_drift_from_certification_is_an_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "evaluator").mkdir()
            (Path(tmp) / "evaluator" / "certification.json").write_text(json.dumps(
                {"trigger_rates": {"a": 1.0}, "program_success_rates": {"a": 1.0}}))
            rows = [_row("c", {"a": "not-fired"}, case_dir=tmp)] * 3 + [_row("c", {"a": "succeeded"}, case_dir=tmp)]
            text = summarize(rows)
            self.assertIn("c/a: fires 0.25 vs certified 1.00", text)

    def test_partial_rate_is_an_alert(self):
        rows = [_row("c", {"a": "not-fired"}, validity="partial")] * 2 + [_row("c", {"a": "succeeded"})]
        self.assertIn("c: 2/3 runs partial", summarize(rows))

    def test_control_rows_are_ignored(self):
        self.assertNotIn("## Norms", summarize([_row("c", None, distractors=False)]))


class QueryLogTypeTests(unittest.TestCase):
    def test_query_logging_configs_are_a_standalone_type_with_a_native_delete(self):
        from harness.extractor.aws.capabilities.registry import CAPABILITY_REGISTRY
        from harness.runtime.case import DELETE_ORDER

        adapter = CAPABILITY_REGISTRY["aws_route53_query_log"]
        self.assertEqual(adapter.cloudcontrol_type, "AWS::Route53::QueryLoggingConfig")
        self.assertTrue(adapter.standalone)
        self.assertEqual(adapter.identifier_from_state({"id": "8889bf65-b363"}), "8889bf65-b363")
        self.assertIn("AWS::Route53::QueryLoggingConfig", DELETE_ORDER)


if __name__ == "__main__":
    unittest.main()
