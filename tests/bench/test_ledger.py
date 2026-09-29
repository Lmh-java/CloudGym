from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.bench import Ledger, LedgerError, rename_partial
from harness.bench.spec import Arm, CaseRef, Cell


def cells(batch: str, n: int) -> list[Cell]:
    arm = Arm("a", "claude", None, n, ("c",), 10.0, 1.0, True, {})
    case = CaseRef("c", Path("/c"), "seed", None)
    return [Cell(batch, arm, case, t) for t in range(1, n + 1)]


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.dir = Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_transitions_and_resume(self) -> None:
        cs = cells("b", 2)
        ledger = Ledger.open(self.dir, batch="b", spec_hash="h1", cells=cs)
        self.assertEqual([c.key for c in ledger.pending(cs)], ["a/c/t1", "a/c/t2"])
        ledger.start(cs[0], self.dir / "a-c-t1")
        ledger.finish(cs[0], "done", verdict="pass")
        ledger.start(cs[1], self.dir / "a-c-t2")
        ledger.finish(cs[1], "interrupted", reason="ctrl-c")
        reopened = Ledger.open(self.dir, batch="b", spec_hash="h1", cells=cs)
        self.assertEqual([c.key for c in reopened.pending(cs)], ["a/c/t2"])
        self.assertEqual(reopened.entry("a/c/t1")["attempts"][0]["verdict"], "pass")
        self.assertEqual(reopened.counts(), {"done": 1, "interrupted": 1})
        with self.assertRaises(LedgerError):
            reopened.start(cs[0], self.dir / "x")

    def test_drift_orphans_and_reconcile(self) -> None:
        cs = cells("b", 2)
        ledger = Ledger.open(self.dir, batch="b", spec_hash="h1", cells=cs)
        ledger.start(cs[0], self.dir / "a-c-t1")
        # spec shrank and changed hash; process died mid-cell
        reopened = Ledger.open(self.dir, batch="b", spec_hash="h2", cells=cs[:1])
        self.assertTrue(reopened.entry("a/c/t2")["orphaned"])
        self.assertEqual(reopened.reconcile_running(cs[:1]), ["a/c/t1"])
        self.assertEqual(reopened.status("a/c/t1"), "interrupted")
        events = [json.loads(l)["event"] for l in (self.dir / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events, ["cell-start", "spec-drift", "cell-reconciled"])
        with self.assertRaises(LedgerError):
            Ledger.open(self.dir, batch="other", spec_hash="h2", cells=cs)

    def test_contaminated_is_terminal_until_released(self) -> None:
        cs = cells("b", 2)
        ledger = Ledger.open(self.dir, batch="b", spec_hash="h1", cells=cs)
        ledger.start(cs[0], self.dir / "a-c-t1")
        ledger.finish(cs[0], "done", verdict="pass")
        self.assertTrue(ledger.mark_contaminated("a/c/t1", reason="audit: 2 read(s) outside the workspace"))
        self.assertFalse(ledger.mark_contaminated("a/c/t2", reason="x"))     # pending: nothing to retire
        reopened = Ledger.open(self.dir, batch="b", spec_hash="h1", cells=cs)
        self.assertEqual(reopened.status("a/c/t1"), "contaminated")
        self.assertEqual([c.key for c in reopened.pending(cs)], ["a/c/t2"])
        self.assertEqual(reopened.counts(), {"contaminated": 1, "pending": 1})
        with self.assertRaises(LedgerError):
            reopened.start(cs[0], self.dir / "x")
        self.assertEqual(reopened.entry("a/c/t1")["attempts"][0]["verdict"], "pass")   # history kept
        reopened.requeue("a/c/t1", reason="released")
        self.assertEqual([c.key for c in reopened.pending(cs)], ["a/c/t1", "a/c/t2"])
        events = [json.loads(l)["event"] for l in (self.dir / "events.jsonl").read_text().splitlines()]
        self.assertIn("cell-contaminated", events)

    def test_auto_requeue_budget_counts_finished_attempts_only(self) -> None:
        cs = cells("b", 4)
        ledger = Ledger.open(self.dir, batch="b", spec_hash="h1", cells=cs)
        # t1: harness fault once -> rerun 2/3
        ledger.start(cs[0], self.dir / "1"); ledger.finish(cs[0], "failed", reason="distractor task was cancelled")
        # t2: contaminated after many rate-limit interruptions -> interruptions do not count, rerun 2/3
        for _ in range(5):
            ledger.start(cs[1], self.dir / "2"); ledger.finish(cs[1], "interrupted", reason="rate-limited: session limit")
        ledger.start(cs[1], self.dir / "2"); ledger.finish(cs[1], "done", verdict="pass")
        ledger.mark_contaminated("a/c/t2", reason="audit: 1 read(s) outside the workspace")
        # t3: three finished attempts already -> exhausted, reported once
        for _ in range(3):
            ledger.start(cs[2], self.dir / "3"); ledger.finish(cs[2], "failed", reason="snapshot observer failed")
            if ledger.status("a/c/t3") == "failed" and len(ledger.entry("a/c/t3")["attempts"]) < 3:
                ledger.requeue("a/c/t3")
        # t4: a model's wrong answer is `done`, never rerun
        ledger.start(cs[3], self.dir / "4"); ledger.finish(cs[3], "done", verdict="fail")

        requeued, exhausted = ledger.auto_requeue(cs, max_attempts=3)
        self.assertEqual([k for k, _ in requeued], ["a/c/t1", "a/c/t2"])
        self.assertIn("auto-rerun 2/3: failed (distractor task was cancelled)", requeued[0][1])
        self.assertIn("auto-rerun 2/3: contaminated (audit:", requeued[1][1])
        self.assertEqual(exhausted, ["a/c/t3"])
        self.assertEqual([c.key for c in ledger.pending(cs)], ["a/c/t1", "a/c/t2"])
        self.assertEqual(ledger.status("a/c/t3"), "failed")
        self.assertEqual(ledger.status("a/c/t4"), "done")
        self.assertEqual(len(ledger.entry("a/c/t2")["attempts"]), 6)          # history kept
        self.assertEqual(ledger.auto_requeue(cs, max_attempts=3), ([], []))   # exhausted reported once
        events = [json.loads(l)["event"] for l in (self.dir / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events.count("cell-auto-rerun-exhausted"), 1)

    def test_rename_partial(self) -> None:
        run = self.dir / "t1"
        run.mkdir()
        self.assertEqual(rename_partial(run), self.dir / "t1.int1")
        run.mkdir()
        self.assertEqual(rename_partial(run), self.dir / "t1.int2")
        self.assertIsNone(rename_partial(run))



if __name__ == "__main__":
    unittest.main()


class HoldTests(unittest.TestCase):
    """``arm.hold``: cells are queued in the ledger but never pending for a run."""

    def test_held_cells_are_created_but_not_pending(self) -> None:
        import tempfile
        from pathlib import Path
        from harness.bench.spec import Arm, CaseRef, Cell
        from harness.bench.ledger import Ledger
        case = CaseRef(name="c", path=Path("/c"), seed_id="s", case_dir=None)
        run = Arm(name="run", agent="claude", model="m", trials=1, cases=("c",), timeout=1, poll_interval=1, intercept=True)
        held = Arm(name="held", agent="claude", model="m", trials=1, cases=("c",), timeout=1, poll_interval=1, intercept=True, hold=True)
        cells = [Cell("b", run, case, 1), Cell("b", held, case, 1)]
        with tempfile.TemporaryDirectory() as d:
            ledger = Ledger.open(Path(d), batch="b", spec_hash="x", cells=cells)
            self.assertEqual([c.key for c in ledger.pending(cells)], ["run/c/t1"])
            self.assertEqual([c.key for c in ledger.held(cells)], ["held/c/t1"])
            self.assertEqual(ledger.counts(), {"pending": 1, "pending (held)": 1})
            self.assertTrue(ledger.entry("held/c/t1")["held"])
            # lifting the hold on re-open releases the cell without touching its status
            released = Arm(name="held", agent="claude", model="m", trials=1, cases=("c",), timeout=1, poll_interval=1, intercept=True)
            cells2 = [Cell("b", run, case, 1), Cell("b", released, case, 1)]
            ledger = Ledger.open(Path(d), batch="b", spec_hash="x", cells=cells2)
            self.assertEqual(len(ledger.pending(cells2)), 2)
            self.assertNotIn("held", ledger.entry("held/c/t1"))
