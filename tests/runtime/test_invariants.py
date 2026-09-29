"""Invariant monitor, controller integration, and module loading."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.runtime import invariant
from harness.runtime.config import declared_invariant
from harness.runtime.controller import EventController
from harness.runtime.decorators import load_invariant_metadata
from harness.runtime.invariants import InvariantDefinition, InvariantMonitor, InvariantSpec
from harness.runtime.store import JsonlEventStore


def _vpc_present(snapshot) -> bool:
    return bool(snapshot.get("resources", {}).get("AWS::EC2::VPC"))


def _snap(vpc: bool) -> dict:
    return {"resources": {"AWS::EC2::VPC": {"vpc-1": {}} if vpc else {}}}


class InvariantMonitorTests(unittest.TestCase):
    def test_violation_and_restoration_are_recorded_once_each(self) -> None:
        monitor = InvariantMonitor((InvariantSpec("vpc", _vpc_present),))
        seq = iter(range(1, 100))

        def observe(vpc: bool, initial: bool = False):
            n = next(seq)
            return monitor.observe(_snap(vpc), observation_id=f"o{n}", snapshot_id=f"s{n}",
                                   sequence=n, initial=initial)

        self.assertEqual(observe(True, initial=True), [])
        self.assertEqual(observe(True), [])
        violated = observe(False)
        self.assertEqual([e.kind for e in violated], ["invariant.violated"])
        self.assertEqual(observe(False), [], "an open violation is not re-reported")
        restored = observe(True)
        self.assertEqual([e.kind for e in restored], ["invariant.restored"])
        self.assertEqual(restored[0].data["violated_observation_id"], "o3")

        summary = monitor.summary()
        self.assertEqual(summary["violated"], ["vpc"])
        self.assertEqual(summary["unrestored"], [])
        self.assertIsNone(summary["invalid_reason"])
        record = summary["invariants"]["vpc"]
        self.assertEqual(record["checks"], 5)
        self.assertEqual(record["violation_count"], 1)
        self.assertTrue(record["holds_at_end"])
        v = record["violations"][0]
        self.assertEqual((v["snapshot_id"], v["restored_snapshot_id"], v["restored"]), ("s3", "s5", True))

    def test_unrestored_violation_is_reported_at_end(self) -> None:
        monitor = InvariantMonitor((InvariantSpec("vpc", _vpc_present),))
        monitor.observe(_snap(True), observation_id="o1", snapshot_id="S0", sequence=1, initial=True)
        monitor.observe(_snap(False), observation_id="o2", snapshot_id="p1", sequence=2)
        summary = monitor.summary()
        self.assertEqual(summary["unrestored"], ["vpc"])
        self.assertFalse(summary["invariants"]["vpc"]["holds_at_end"])
        self.assertIsNone(summary["invalid_reason"], "a real violation is evidence, not an error")

    def test_initial_violation_invalidates_the_run(self) -> None:
        monitor = InvariantMonitor((InvariantSpec("vpc", _vpc_present),))
        events = monitor.observe(_snap(False), observation_id="o1", snapshot_id="S0",
                                 sequence=1, initial=True)
        self.assertEqual(events[0].kind, "invariant.violated")
        self.assertTrue(events[0].data["initial"])
        self.assertIn("initial state", monitor.invalid_reason)

    def test_check_initial_false_skips_s0(self) -> None:
        monitor = InvariantMonitor((InvariantSpec("vpc", _vpc_present, check_initial=False),))
        self.assertEqual(
            monitor.observe(_snap(False), observation_id="o1", snapshot_id="S0", sequence=1, initial=True),
            [],
        )
        self.assertIsNone(monitor.invalid_reason)
        self.assertEqual(monitor.summary()["invariants"]["vpc"]["checks"], 0)

    def test_predicate_exception_fails_closed_and_stops_checking(self) -> None:
        def boom(_snapshot):
            raise KeyError("missing")

        monitor = InvariantMonitor((InvariantSpec("bad", boom), InvariantSpec("vpc", _vpc_present)))
        events = monitor.observe(_snap(True), observation_id="o1", snapshot_id="p1", sequence=1)
        self.assertEqual([e.kind for e in events], ["invariant.check_failed"])
        self.assertIn("predicate failed", monitor.invalid_reason)
        # The failed invariant is not re-evaluated; the healthy one still is.
        monitor.observe(_snap(True), observation_id="o2", snapshot_id="p2", sequence=2)
        summary = monitor.summary()
        self.assertEqual(summary["check_failed"], ["bad"])
        self.assertEqual(summary["invariants"]["bad"]["checks"], 1)
        self.assertEqual(summary["invariants"]["vpc"]["checks"], 2)

    def test_duplicate_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique"):
            InvariantMonitor((InvariantSpec("a", _vpc_present), InvariantSpec("a", _vpc_present)))


class ControllerInvariantTests(unittest.IsolatedAsyncioTestCase):
    async def test_controller_logs_transitions_in_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = JsonlEventStore(root / "events.jsonl")
            controller = EventController("run", store, invariants=(InvariantSpec("vpc", _vpc_present),))
            await controller.observe_snapshot(_snap(True), snapshot_id="S0", initial=True)
            await controller.observe_snapshot(_snap(False), snapshot_id="poll-1")
            await controller.observe_snapshot(_snap(True), snapshot_id="poll-2")
            self.assertIsNone(controller.invalid_reason)
            await controller.finish(timeout=1)
            store.close()
            records = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            kinds = [(r["kind"], r.get("sequence")) for r in records]
            self.assertEqual(
                [k for k, _ in kinds],
                ["snapshot.observed", "snapshot.observed", "invariant.violated",
                 "snapshot.observed", "invariant.restored", "run.event_controller_finished"],
            )
            self.assertEqual([s for _, s in kinds], list(range(1, 7)), "one global sequence")
            finished = records[-1]["data"]
            self.assertEqual(finished["violated_invariants"], ["vpc"])
            self.assertEqual(finished["unrestored_invariants"], [])
            self.assertEqual(controller.invariant_summary()["violated"], ["vpc"])

    async def test_initial_violation_marks_controller_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JsonlEventStore(Path(temp) / "events.jsonl")
            controller = EventController("run", store, invariants=(InvariantSpec("vpc", _vpc_present),))
            await controller.observe_snapshot(_snap(False), snapshot_id="S0", initial=True)
            self.assertIn("initial state", controller.invalid_reason)
            store.close()


INVARIANT_MODULE = '''
from harness.runtime import invariant

@invariant(
    name="vpc-present",
    description="The case VPC must never disappear.",
    predicate=lambda s: bool(s.get("resources", {}).get("AWS::EC2::VPC")),
)
def vpc_present():
    """Documentation only."""
'''


class InvariantModuleTests(unittest.TestCase):
    def test_declared_invariant_loads_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invariant.py"
            path.write_text(INVARIANT_MODULE)
            spec = declared_invariant(InvariantDefinition("vpc", path))
            self.assertEqual(spec.invariant_id, "vpc")
            self.assertEqual(spec.metadata["name"], "vpc-present")
            self.assertTrue(spec.check_initial)
            self.assertTrue(spec.holds(_snap(True)))
            self.assertFalse(spec.holds(_snap(False)))

    def test_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invariant.py"
            path.write_text(INVARIANT_MODULE)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                declared_invariant(InvariantDefinition("vpc", path, sha256="0" * 64))

    def test_module_must_declare_exactly_one_invariant(self) -> None:
        class Empty:
            pass

        with self.assertRaisesRegex(ValueError, "exactly one @invariant"):
            load_invariant_metadata(Empty)

    def test_decorator_validates_arguments(self) -> None:
        with self.assertRaises(TypeError):
            invariant(name="x", description="y", predicate="not callable")
        with self.assertRaises(ValueError):
            invariant(name="", description="y", predicate=_vpc_present)


if __name__ == "__main__":
    unittest.main()
