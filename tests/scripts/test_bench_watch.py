"""``bench watch``: the accumulate loop over ``cases_from`` (runner mocked, no AWS)."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.bench import BatchResult, load_spec
from harness.bench.routes import RouteBook
from scripts import bench
from tests.bench.test_spec import SEED, make_tree


class WatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name).resolve()
        self.seeds, self.case_a, self.case_b = make_tree(self.root)
        (self.root / "experiments").mkdir()
        self.spec_path = self.root / "experiments" / "acc.yml"
        self.spec_path.write_text("batch: acc\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n"
                                  "  - {name: a1, model: m1}\n  - {name: a2, model: m2}\n")
        self.batch_dir = self.root / "artifacts" / "acc"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _spec(self):
        return load_spec(self.spec_path, seeds_dir=self.seeds, default_artifacts=self.root / "artifacts")

    def _write_ledger(self, statuses: dict[str, str]) -> None:
        self.batch_dir.mkdir(parents=True, exist_ok=True)
        (self.batch_dir / "ledger.json").write_text(json.dumps(
            {"batch": "acc", "spec_hash": "x", "cells": {k: {"status": v, "attempts": []} for k, v in statuses.items()}}))

    def test_pending_keys_reads_ledger_without_writing(self) -> None:
        cells = self._spec().cells()
        self.assertEqual(len(bench.pending_keys(self.batch_dir, cells)), 4)       # no ledger: all pending
        self._write_ledger({"a1/case-a/t1": "done", "a1/case-b/t1": "failed", "a2/case-a/t1": "interrupted"})
        self.assertEqual(bench.pending_keys(self.batch_dir, cells), ["a2/case-a/t1", "a2/case-b/t1"])
        self.assertFalse((self.batch_dir / "ledger.json").read_text().count("a2/case-b"))   # untouched

    def test_watch_once_runs_only_when_pending(self) -> None:
        self._write_ledger({k: "done" for k in ("a1/case-a/t1", "a1/case-b/t1", "a2/case-a/t1", "a2/case-b/t1")})
        args = argparse.Namespace(spec=self.spec_path, allow_aws=True, only=None, region=None, batch_dir=self.batch_dir,
                                  slots=None, allow_dirty=True, interval=0.0, once=True, keep_going=False, fresh=False)
        calls = []

        def fake_run(spec, batch_dir, a, **kw):
            calls.append([c.key for c in spec.cells() if c.key in bench.pending_keys(batch_dir, spec.cells())])
            return BatchResult(batch_dir, ran=[], outcomes={}, stopped_reason=None)

        with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(self.root)), patch.object(bench, "_load", lambda p: self._spec()), patch.object(bench, "_run_spec", fake_run):
            self.assertEqual(bench.cmd_watch(args), 0)
            self.assertEqual(calls, [])                        # nothing pending, runner not invoked
            case_c = self.root / "cases" / "case-c"            # casegen converts a new case
            (case_c / "agent").mkdir(parents=True)
            (case_c / "agent" / "task.json").write_text(json.dumps({"seed_id": SEED}))
            self.assertEqual(bench.cmd_watch(args), 0)
            self.assertEqual(calls, [["a1/case-c/t1", "a2/case-c/t1"]])

    def test_watch_auto_reruns_failed_and_contaminated_before_the_pass(self) -> None:
        def attempts(*outcomes):
            return [{"n": i + 1, "outcome": o, "reason": "distractor task was cancelled"} for i, o in enumerate(outcomes)]
        self.batch_dir.mkdir(parents=True, exist_ok=True)
        (self.batch_dir / "ledger.json").write_text(json.dumps({"batch": "acc", "spec_hash": "x", "cells": {
            "a1/case-a/t1": {"status": "failed", "attempts": attempts("failed")},
            "a1/case-b/t1": {"status": "contaminated", "attempts": attempts("done"), "contaminated": {"reason": "audit"}},
            "a2/case-a/t1": {"status": "failed", "attempts": attempts("failed", "failed", "failed")},
            "a2/case-b/t1": {"status": "done", "attempts": attempts("done")}}}))
        args = argparse.Namespace(spec=self.spec_path, allow_aws=True, only=None, region=None, batch_dir=self.batch_dir,
                                  slots=None, allow_dirty=True, interval=0.0, once=True, keep_going=False, fresh=False,
                                  auto_rerun=3)
        calls = []

        def fake_run(spec, batch_dir, a, **kw):
            calls.append(bench.pending_keys(batch_dir, spec.cells()))
            return BatchResult(batch_dir, ran=[], outcomes={}, stopped_reason=None)

        with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(self.root)), patch.object(bench, "_load", lambda p: self._spec()), patch.object(bench, "_run_spec", fake_run):
            self.assertEqual(bench.cmd_watch(args), 0)
        self.assertEqual(calls, [["a1/case-a/t1", "a1/case-b/t1"]])
        cells = json.loads((self.batch_dir / "ledger.json").read_text())["cells"]
        self.assertEqual(cells["a2/case-a/t1"]["status"], "failed")
        self.assertTrue(cells["a2/case-a/t1"]["auto_rerun_exhausted"])

        args.auto_rerun = 1                                     # off: nothing flips
        (self.batch_dir / "ledger.json").write_text(json.dumps({"batch": "acc", "spec_hash": "x", "cells": {
            k: {"status": "failed", "attempts": attempts("failed")} for k in
            ("a1/case-a/t1", "a1/case-b/t1", "a2/case-a/t1", "a2/case-b/t1")}}))
        calls.clear()
        with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(self.root)), patch.object(bench, "_load", lambda p: self._spec()), patch.object(bench, "_run_spec", fake_run):
            self.assertEqual(bench.cmd_watch(args), 0)
        self.assertEqual(calls, [])

    def test_start_watch_argv(self) -> None:
        args = argparse.Namespace(spec=self.spec_path, only=None, region=None, slots=None, allow_dirty=True,
                                  watch=True, interval=45.0, limit_backoff=600.0)
        argv = bench._run_argv(args, self.batch_dir)
        self.assertIn("watch", argv)
        self.assertNotIn("run", argv)
        self.assertEqual(argv[argv.index("--interval") + 1], "45.0")
        self.assertIn("--keep-going", argv)
        self.assertEqual(argv[argv.index("--limit-backoff") + 1], "600.0")
        self.assertEqual(argv[argv.index("--auto-rerun") + 1], "3")
        self.assertIn("--allow-dirty", argv)


class HoldWatchTests(unittest.TestCase):
    def test_pending_keys_skip_held_arms(self) -> None:
        import tempfile
        from tests.bench.test_spec import make_tree
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            seeds, _, _ = make_tree(root)
            (root / "experiments").mkdir()
            spec_path = root / "experiments" / "h.yml"
            spec_path.write_text("batch: h\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n"
                                 "  - {name: go, model: m1}\n  - {name: wait, model: m2, hold: true}\n")
            spec = load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts")
            self.assertTrue(spec.arms[1].hold)
            keys = bench.pending_keys(root / "artifacts" / "h", spec.cells())
            self.assertEqual(keys, ["go/case-a/t1", "go/case-b/t1"])
            # the hold does not change the spec hash
            spec_path.write_text(spec_path.read_text().replace(", hold: true", ""))
            self.assertEqual(load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts").spec_hash, spec.spec_hash)

    def test_order_is_scheduling_only(self) -> None:
        import tempfile
        from harness.bench.spec import SpecError
        from tests.bench.test_spec import make_tree
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            seeds, _, _ = make_tree(root)
            (root / "experiments").mkdir()
            spec_path = root / "experiments" / "o.yml"
            spec_path.write_text("batch: o\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\narms:\n"
                                 "  - {name: last, model: m1, order: 1}\n  - {name: first, model: m2}\n")
            spec = load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts")
            self.assertEqual([a.order for a in spec.arms], [1, 0])
            spec_path.write_text(spec_path.read_text().replace(", order: 1", ""))
            self.assertEqual(load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts").spec_hash, spec.spec_hash)
            spec_path.write_text(spec_path.read_text().replace("model: m1", "model: m1, order: late"))
            with self.assertRaises(SpecError):
                load_spec(spec_path, seeds_dir=seeds, default_artifacts=root / "artifacts")


class TrialTwoGateTests(unittest.TestCase):
    """A trial-2 batch waits for the trial-1 batches (`after`) and runs its order-1 arms only when
    neither it nor its peer has a runnable lower-order cell (`peers`)."""

    def setUp(self) -> None:
        import tempfile
        from tests.bench.test_spec import make_tree
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name).resolve()
        self.seeds, _, _ = make_tree(self.root)
        exp = self.root / "experiments"
        exp.mkdir()
        arms = "arms:\n  - {name: haiku, model: m1}\n  - {name: fable, model: m2, order: 1}\n"
        (exp / "t1.yml").write_text("batch: t1\ndefaults: {agent: claude, trials: 1}\ncases_from: ../cases\n" + arms)
        for name, peer in (("a2", "b2"), ("b2", "a2")):
            (exp / f"{name}.yml").write_text(f"batch: {name}\ntrials_from: 2\nafter: [t1.yml]\npeers: [{peer}.yml]\n"
                                             "defaults: {agent: claude, trials: 2}\ncases_from: ../cases\n" + arms)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _load(self, p):
        return load_spec(Path(p), seeds_dir=self.seeds, default_artifacts=self.root / "artifacts")

    def _ledger(self, batch: str, statuses: dict[str, str]) -> None:
        d = self.root / "artifacts" / batch
        d.mkdir(parents=True, exist_ok=True)
        (d / "ledger.json").write_text(json.dumps({"batch": batch, "spec_hash": "x",
                                                   "cells": {k: {"status": v, "attempts": []} for k, v in statuses.items()}}))

    def _watch_once(self, name: str) -> list[list[str]]:
        calls = []

        def fake_run(spec, batch_dir, a, **kw):
            calls.append(sorted(k for k in bench.pending_keys(batch_dir, spec.cells())
                                if kw.get("max_order") is None or spec.arms[[x.name for x in spec.arms].index(k.split("/")[0])].order <= kw["max_order"]))
            return BatchResult(batch_dir, ran=[], outcomes={}, stopped_reason=None)

        args = argparse.Namespace(spec=self.root / "experiments" / f"{name}.yml", allow_aws=True, only=None, region=None,
                                  batch_dir=None, slots=None, allow_dirty=True, interval=0.0, once=True, keep_going=False,
                                  fresh=False, auto_rerun=3)
        with patch.object(bench, "_route_book", lambda *a, **k: RouteBook(self.root)), \
                patch.object(bench, "_load", self._load), patch.object(bench, "_run_spec", fake_run):
            bench.cmd_watch(args)
        return calls

    def test_trial_two_waits_for_trial_one_then_fable_waits_for_both_configs(self) -> None:
        spec = self._load(self.root / "experiments" / "a2.yml")
        self.assertEqual(sorted({c.trial for c in spec.cells()}), [2])
        self.assertEqual(self._watch_once("a2"), [], "trial 1 has runnable cells: trial 2 waits")
        a2 = self.root / "artifacts" / "a2"
        self.assertEqual(len(json.loads((a2 / "ledger.json").read_text())["cells"]), 4, "a gated batch shows its cells")
        self.assertIn("t1 goes first", json.loads((a2 / "watch-state.json").read_text())["waiting"])
        t1_done = {f"{arm}/{case}/t1": "done" for arm in ("haiku", "fable") for case in ("case-a", "case-b")}
        self._ledger("t1", t1_done)
        # a2 runs its non-Fable cells only: fable (order 1) waits for order 0 in a2 and b2
        self.assertEqual(self._watch_once("a2"), [["haiku/case-a/t2", "haiku/case-b/t2"]])
        self._ledger("a2", {"haiku/case-a/t2": "done", "haiku/case-b/t2": "done"})
        self.assertEqual(self._watch_once("a2"), [], "b2 still has non-Fable trial-2 cells")
        self._ledger("b2", {"haiku/case-a/t2": "done", "haiku/case-b/t2": "done"})
        self.assertEqual(self._watch_once("a2"), [["fable/case-a/t2", "fable/case-b/t2"]])

    def test_a_spent_route_does_not_block_the_next_trial(self) -> None:
        from harness.bench.routes import Route
        # trial 1 has only Fable left and Fable's window is spent (no fallback): trial 2 may start
        self._ledger("t1", {f"haiku/{c}/t1": "done" for c in ("case-a", "case-b")})
        RouteBook(self.root).note_limited(Route("subscription", {}, key="subscription:m2"),
                                          "You've hit your weekly limit · resets in 24 hours")
        self.assertEqual(self._watch_once("a2"), [["haiku/case-a/t2", "haiku/case-b/t2"]])
