import unittest

from harness.runtime.events import Snapshot
from harness.runtime.matcher import SnapshotMatcher


class SnapshotLambdaMatcherTests(unittest.TestCase):
    def test_lambda_receives_current_snapshot(self) -> None:
        matcher = SnapshotMatcher(
            predicates=(lambda snapshot: snapshot.get("status") == "ready",)
        )
        self.assertTrue(matcher.matches({"status": "ready"}))
        self.assertFalse(matcher.matches({"status": "pending"}))

    def test_snapshot_has_typed_common_fields_and_mapping_compatibility(self) -> None:
        snapshot = Snapshot.from_value({
            "provider": "aws",
            "captured_at": "2026-08-16T00:00:00Z",
            "resources": {"aws_vpc/main": {"state": "available"}},
            "case_specific": {"ready": True},
        })
        self.assertEqual(snapshot.provider, "aws")
        self.assertEqual(snapshot.resources["aws_vpc/main"]["state"], "available")
        self.assertTrue(snapshot["case_specific"]["ready"])

    def test_lambda_failure_is_reported_as_match_error(self) -> None:
        matcher = SnapshotMatcher(predicates=(lambda snapshot: snapshot["missing"],))
        with self.assertRaisesRegex(RuntimeError, "snapshot predicate failed"):
            matcher.matches({})
