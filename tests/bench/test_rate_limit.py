"""Token exhaustion: classification, re-queue, and the `bench requeue` command (no AWS)."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.bench.ledger import Ledger
from harness.bench.runner import rate_limit_reason
from harness.bench.spec import Arm, CaseRef, Cell
from harness.bench.routes import RouteBook
from scripts import bench


def _cells():
    case = CaseRef(name="c", path=Path("/c"), seed_id="s", case_dir=None)
    arm = Arm(name="a", agent="claude", model="m", trials=2, cases=("c",), timeout=1, poll_interval=1, intercept=True)
    return [Cell("b", arm, case, 1), Cell("b", arm, case, 2)]


class ClassifyTests(unittest.TestCase):
    def test_agent_error_and_stop_reason(self) -> None:
        self.assertIsNotNone(rate_limit_reason({"agent": {"error": "AgentRunnerError: codex exited (model at capacity / usage limit)"}}))
        self.assertIsNotNone(rate_limit_reason({"agent": {"stop_reason": "rate_limit_error"}}))
        self.assertIsNone(rate_limit_reason({"agent": {"error": "TerraformError: apply exited 1"}}))
        self.assertIsNone(rate_limit_reason({"agent": {}}))
        # the 2026-09 Claude Code wording, seen on the VM: burned 7 rows before it was matched
        self.assertIsNotNone(rate_limit_reason({"agent": {"error": "You've hit your session limit · resets 5:40pm (UTC)"}}))
        self.assertIsNotNone(rate_limit_reason({"agent": {"error": "You've hit your weekly limit · resets Sep 21"}}))
        self.assertIsNotNone(rate_limit_reason({"agent": {"error": "You've reached your Fable limit. Switch to another model to continue."}}))

    def test_claude_result_event(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / "agent").mkdir()
            events = [{"type": "system", "subtype": "init"},
                      {"type": "result", "subtype": "success", "is_error": True,
                       "result": "Claude AI usage limit reached|1789900000"}]
            (run / "agent" / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
            self.assertIn("usage limit", rate_limit_reason({"agent": {}}, run))
            # any wording, as long as claude says 429 (seen 2026-09-24, retried 15 times before this rule)
            events[-1] = {"type": "result", "is_error": True, "api_error_status": 429, "result": "Some new limit text."}
            (run / "agent" / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
            self.assertEqual(rate_limit_reason({"agent": {}}, run), "Some new limit text.")
            events[-1] = {"type": "result", "subtype": "success", "is_error": False, "result": "Done."}
            (run / "agent" / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
            self.assertIsNone(rate_limit_reason({"agent": {}}, run))


class RequeueTests(unittest.TestCase):
    def test_ledger_requeue_keeps_attempts(self) -> None:
        cells = _cells()
        with tempfile.TemporaryDirectory() as d:
            ledger = Ledger.open(Path(d), batch="b", spec_hash="x", cells=cells)
            ledger.start(cells[0], Path(d) / "r1")
            ledger.finish(cells[0], "failed", reason="Claude AI usage limit reached|123")
            self.assertEqual(ledger.status("a/c/t1"), "failed")
            ledger.requeue("a/c/t1", reason="test")
            self.assertEqual(ledger.status("a/c/t1"), "pending")
            self.assertEqual(len(ledger.entry("a/c/t1")["attempts"]), 1)
            self.assertEqual([c.key for c in ledger.pending(cells)], ["a/c/t1", "a/c/t2"])

    def test_cmd_requeue_matches_rate_limit_reasons_only(self) -> None:
        cells = _cells()
        with tempfile.TemporaryDirectory() as d:
            batch_dir = Path(d) / "b"
            ledger = Ledger.open(batch_dir, batch="b", spec_hash="x", cells=cells)
            ledger.start(cells[0], batch_dir / "r1"); ledger.finish(cells[0], "failed", reason="agent runner: codex exited (usage limit)")
            ledger.start(cells[1], batch_dir / "r2"); ledger.finish(cells[1], "failed", reason="TerraformError: apply exited 1")

            class FakeSpec:
                batch = "b"; spec_hash = "x"
                def cells(self): return cells
            args = argparse.Namespace(spec=Path("x.yml"), match=None, all=False, dry_run=False, batch_dir=batch_dir)
            with patch.object(bench, "_load", lambda p: FakeSpec()):
                self.assertEqual(bench.cmd_requeue(args), 0)
            data = json.loads((batch_dir / "ledger.json").read_text())["cells"]
            self.assertEqual((data["a/c/t1"]["status"], data["a/c/t2"]["status"]), ("pending", "failed"))
            args.all = True
            with patch.object(bench, "_load", lambda p: FakeSpec()):
                bench.cmd_requeue(args)
            data = json.loads((batch_dir / "ledger.json").read_text())["cells"]
            self.assertEqual(data["a/c/t2"]["status"], "pending")


class WatchBackoffTests(unittest.TestCase):
    def test_watch_once_exits_1_on_rate_limit_stop(self) -> None:
        from harness.bench import BatchResult
        from tests.bench.test_spec import make_tree
        from harness.bench.spec import load_spec
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            seeds, _, _ = make_tree(root)
            (root / "experiments").mkdir()
            spec_path = root / "experiments" / "w.yml"
            spec_path.write_text("batch: w\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n  - {name: a, model: m}\n")
            spec = load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts")
            args = argparse.Namespace(spec=spec_path, allow_aws=True, only=None, region=None, batch_dir=root / "artifacts" / "w",
                                      slots=None, allow_dirty=True, interval=0.0, once=True, keep_going=True, limit_backoff=0.0, fresh=False)
            fake = lambda s, b, a, **kw: BatchResult(b, ran=[], outcomes={}, stopped_reason="rate-limited: agent tokens exhausted")  # noqa: E731
            with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(root)), patch.object(bench, "_load", lambda p: spec), patch.object(bench, "_run_spec", fake):
                self.assertEqual(bench.cmd_watch(args), 1)

    def test_watch_backoff_escalates_then_resets(self) -> None:
        from harness.bench import BatchResult
        from tests.bench.test_spec import make_tree
        from harness.bench.spec import load_spec
        self.assertEqual(bench.backoff_schedule("1800,3600"), [1800.0, 3600.0])
        self.assertEqual(bench.backoff_schedule(900.0), [900.0])
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            seeds, _, _ = make_tree(root)
            (root / "experiments").mkdir()
            spec_path = root / "experiments" / "w.yml"
            spec_path.write_text("batch: w\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n  - {name: a, model: m}\n")
            spec = load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts")
            args = argparse.Namespace(spec=spec_path, allow_aws=True, only=None, region=None, batch_dir=root / "artifacts" / "w",
                                      slots=None, allow_dirty=True, interval=0.0, once=False, keep_going=True,
                                      limit_backoff="1,2,4", fresh=False)
            # limited x4 (1, 2, 4, 4), progress (reset), limited (1), then a sixth pass that ends the loop
            script = iter(["rate-limited: x", "rate-limited: x", "rate-limited: x", "rate-limited: x", None, "rate-limited: x"])
            slept: list[float] = []

            class Done(Exception):
                pass

            def fake_run(s, b, a, **kw):
                try:
                    reason = next(script)
                except StopIteration:
                    raise Done
                return BatchResult(b, ran=[], outcomes={}, stopped_reason=reason)

            def fake_sleep(secs):
                slept.append(secs)

            with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(root)), patch.object(bench, "_load", lambda p: spec), patch.object(bench, "_run_spec", fake_run), \
                    patch.object(bench, "pending_keys", lambda bd, cells: ["a/x/t1"]), patch.object(bench.time, "sleep", fake_sleep):
                with self.assertRaises(Done):
                    bench.cmd_watch(args)
            limited = [s for s in slept if s != 0.0]
            self.assertEqual(limited, [1.0, 2.0, 4.0, 4.0, 1.0])

    def test_watch_exits_when_a_pass_is_interrupted(self) -> None:
        from harness.bench import BatchResult
        from tests.bench.test_spec import make_tree
        from harness.bench.spec import load_spec
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            seeds, _, _ = make_tree(root)
            (root / "experiments").mkdir()
            spec_path = root / "experiments" / "w.yml"
            spec_path.write_text("batch: w\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n  - {name: a, model: m}\n")
            spec = load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts")
            args = argparse.Namespace(spec=spec_path, allow_aws=True, only=None, region=None, batch_dir=root / "artifacts" / "w",
                                      slots=None, allow_dirty=True, interval=0.0, once=False, keep_going=True,
                                      limit_backoff="0", fresh=False)
            runs = []
            fake = lambda s, b, a, **kw: runs.append(1) or BatchResult(b, ran=[], outcomes={}, stopped_reason="interrupted")  # noqa: E731
            with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(root)), patch.object(bench, "_load", lambda p: spec), patch.object(bench, "_run_spec", fake), \
                    patch.object(bench, "pending_keys", lambda bd, cells: ["a/x/t1"]):
                self.assertEqual(bench.cmd_watch(args), 130)
            self.assertEqual(runs, [1])


if __name__ == "__main__":
    unittest.main()
