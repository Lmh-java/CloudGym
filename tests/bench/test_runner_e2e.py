"""Batch runner end to end with the fake agent and fake hooks (no AWS)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from harness.aws_safety import AwsTarget
from harness.bench import CellEnv, Ledger, collect_batch, load_spec, run_batch, summarize, write_report
from harness.runtime.coordinator import LifecycleHooks
from harness.sandbox import Pool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runtime"))
from test_run_case_e2e import FAKE_AGENT, FakeHooks  # noqa: E402

SEED = "aws-provider_service_vpc_aws_vpc_p1.tf_0"
SPEC = """
batch: demo
artifacts: ../artifacts
defaults: {agent: claude, timeout: 60, poll_interval: 0.1, intercept: true}
cases:
  - ../cases/case-a
arms:
  - name: base
    trials: 2
  - name: alt
    trials: 1
"""


class ExplodingHooks(FakeHooks):
    async def deploy_initial(self):
        raise RuntimeError("terraform exploded")


class LeakingHooks(FakeHooks):
    async def leak_check(self):
        return {"leaked": [{"type": "AWS::IAM::Role", "identifier": "stranded"}]}


POOL_TARGETS = [AwsTarget(f"pool-{i}", str(i) * 12, "us-east-1", name=f"sbx-{i}") for i in (1, 2, 3)]


class BatchRunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name).resolve()
        seed = self.root / "seeds" / SEED
        (seed / "initial").mkdir(parents=True)
        (seed / "source.json").write_text(json.dumps({"utterance": "Add a subnet.", "resource_types": ["aws_vpc"]}))
        (seed / "initial" / "main.tf").write_text('resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n')
        case = self.root / "cases" / "case-a"
        (case / "agent").mkdir(parents=True)
        (case / "agent" / "task.json").write_text(json.dumps({"seed_id": SEED}))
        (self.root / "experiments").mkdir()
        self.spec_path = self.root / "experiments" / "demo.yml"
        self.spec_path.write_text(SPEC)
        self.agent = self.root / "claude"
        self.agent.write_text(FAKE_AGENT.replace("#!PYTHON", f"#!{sys.executable}", 1))
        self.agent.chmod(0o700)
        os.environ["MARKER_PATH"] = str(self.root / "marker")
        import scripts.run_case as run_case_module
        self._seeds_backup = run_case_module.SEEDS_DIR
        run_case_module.SEEDS_DIR = self.root / "seeds"

    def tearDown(self) -> None:
        import scripts.run_case as run_case_module
        run_case_module.SEEDS_DIR = self._seeds_backup
        os.environ.pop("MARKER_PATH", None)
        self._temp.cleanup()

    def _spec(self):
        return load_spec(self.spec_path, seeds_dir=self.root / "seeds", default_artifacts=self.root / "artifacts")

    def _cell_env(self, cell, target=None) -> CellEnv:
        return CellEnv(region="us-east-1",
                       agent_env={"FAKE_AGENT_MODE": "finish", "PATH": f"{self.root}:{os.environ['PATH']}"},
                       lifecycle_env={"AWS_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "AKIAFAKE", "AWS_SECRET_ACCESS_KEY": "x"},
                       metadata={"versions": {"git_sha": "test"}})

    async def test_batch_runs_resumes_and_reports(self) -> None:
        spec = self._spec()
        calls = {"n": 0}

        def hooks_factory(cell, run_dir, env):
            calls["n"] += 1
            hooks = ExplodingHooks() if calls["n"] == 2 else FakeHooks()
            return hooks.lifecycle_hooks(), None

        # Cells: base/case-a/t1, alt/case-a/t1, base/case-a/t2 (trial-major).
        # Patch RunOptions agent executable through arm args is reserved, so inject via env PATH:
        # the fake agent is found as "claude" because we prepend its dir to PATH.
        env_patch = {"PATH": f"{self.root}:{os.environ['PATH']}"}

        def cell_env(cell, target):
            e = self._cell_env(cell, target)
            e.agent_env.update(env_patch)
            return e

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=cell_env, log=lambda m: None)
        batch_dir = result.batch_dir
        self.assertRegex(batch_dir.name, r"^demo-\d{8}-\d{6}$")
        self.assertEqual(spec.latest_batch_dir(), batch_dir)
        self.assertEqual(result.outcomes, {"base/case-a/t1": "done", "alt/case-a/t1": "failed", "base/case-a/t2": "done"})
        ledger = Ledger.open(batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        self.assertEqual(ledger.counts(), {"done": 2, "failed": 1})
        self.assertTrue((batch_dir / "spec.snapshot.yml").is_file())
        self.assertTrue((batch_dir / "base-case-a-t1" / "result.json").is_file())
        events = [json.loads(l)["event"] for l in (batch_dir / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events[0], "batch-start")
        # report refreshed automatically after each cell
        self.assertTrue((batch_dir / "results.csv").is_file())
        self.assertIn("| base | case-a |", (batch_dir / "summary.md").read_text())
        self.assertIn("batch-complete", events)

        # A rerun has nothing pending: failed is terminal, done is kept.
        with _PathPrepend(self.root):
            again = await run_batch(spec, hooks_factory=hooks_factory, cell_env=cell_env, batch_dir=batch_dir,
                                    log=lambda m: None)
        self.assertEqual(again.ran, [])
        self.assertEqual(len(spec.launches()), 1)

        rows = collect_batch(batch_dir)
        # The exploded cell still has a row (status aborted): failures are data too.
        self.assertEqual(sorted((r.arm, r.trial, r.status) for r in rows),
                         [("alt", 1, "aborted"), ("base", 1, "completed"), ("base", 2, "completed")])
        base_row = next(r for r in rows if r.arm == "base")
        self.assertEqual((base_row.model, base_row.denied_tool_calls, base_row.trigger_fired), ("fake-model", 1, False))
        csv_path, md_path = write_report(rows, batch_dir, title="demo")
        self.assertEqual(len(csv_path.read_text().splitlines()), 4)
        text = md_path.read_text()
        self.assertIn("| base | case-a | 2 | 2/2 | 0 |", text)
        self.assertIn("| alt | case-a | 1 | 0/0 | 1 | 0 |", text)   # aborted: invalid, not a fail
        self.assertIn("## Comparison", text)

    async def test_interrupted_cell_is_requeued(self) -> None:
        spec = self._spec()

        def hooks_factory(cell, run_dir, env):
            raise KeyboardInterrupt

        result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=self._cell_env, log=lambda m: None)
        self.assertEqual(result.stopped_reason, "interrupted")
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        self.assertEqual(ledger.status("base/case-a/t1"), "interrupted")
        self.assertEqual(len(ledger.pending(spec.cells())), 3)


    async def test_pool_spreads_cells_and_releases_clean(self) -> None:
        spec = self._spec()
        pool = Pool(POOL_TARGETS, self.root / "pool")
        seen: list[str] = []

        def hooks_factory(cell, run_dir, env):
            seen.append(env.metadata["sandbox"])
            return FakeHooks().lifecycle_hooks(), None

        def cell_env(cell, target):
            e = self._cell_env(cell, target)
            e.metadata["sandbox"] = target.label
            return e

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=cell_env, pool=pool,
                                     concurrency=3, log=lambda m: None)
        self.assertIsNone(result.stopped_reason)
        self.assertEqual(sorted(result.outcomes.values()), ["done", "done", "done"])
        # three cells, three accounts, three workers: every account used once, all back to clean
        self.assertEqual(sorted(seen), ["sbx-1", "sbx-2", "sbx-3"])
        self.assertEqual(pool.counts(), {"clean": 3})
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        accounts = sorted(ledger.entry(c.key)["attempts"][-1]["account"] for c in spec.cells())
        self.assertEqual(accounts, ["sbx-1", "sbx-2", "sbx-3"])

    async def test_leak_dirties_one_account_and_batch_continues(self) -> None:
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:2], self.root / "pool")
        calls = {"n": 0}

        def hooks_factory(cell, run_dir, env):
            calls["n"] += 1
            hooks = LeakingHooks() if calls["n"] == 1 else FakeHooks()
            return hooks.lifecycle_hooks(), None

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=self._cell_env, pool=pool,
                                     concurrency=1, log=lambda m: None)
        # the leaking cell completed (it is data), its account is dirty, the other two cells ran on sbx-2
        self.assertIsNone(result.stopped_reason)
        self.assertEqual(sorted(result.outcomes.values()), ["done", "done", "done"])
        rows = {r["label"]: r for r in pool.status()}
        self.assertEqual(rows["sbx-1"]["state"], "dirty")
        self.assertIn("teardown not proven clean", rows["sbx-1"]["last_error"])
        self.assertEqual(rows["sbx-2"]["state"], "clean")

        # a second leak with no clean account left stops the batch instead of waiting forever
        pool2 = Pool(POOL_TARGETS[:1], self.root / "pool2")
        spec2 = self._spec()
        calls["n"] = 0

        def leaky(cell, run_dir, env):
            return LeakingHooks().lifecycle_hooks(), None

        with _PathPrepend(self.root):
            result2 = await run_batch(spec2, hooks_factory=leaky, cell_env=self._cell_env, pool=pool2,
                                      concurrency=1, log=lambda m: None)
        self.assertIn("no clean sandbox account", result2.stopped_reason)
        self.assertEqual(len(result2.ran), 1)
        self.assertEqual(pool2.counts(), {"dirty": 1})

    async def test_pre_deploy_error_is_retried_and_keeps_account_clean(self) -> None:
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:1], self.root / "pool")
        calls = {"n": 0}

        def hooks_factory(cell, run_dir, env):
            calls["n"] += 1
            if calls["n"] == 1:
                # looks like a terraform init/plan failure: logs exist, no apply-initial
                logs = run_dir / "private" / "terraform-logs"
                logs.mkdir(parents=True)
                (logs / "001-init.log.jsonl").write_text("")
                (logs / "002-plan-initial.log.jsonl").write_text("")
                raise RuntimeError("Failed to load plugin schemas")
            return FakeHooks().lifecycle_hooks(), None

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=self._cell_env, pool=pool,
                                     concurrency=1, log=lambda m: None)
        self.assertIsNone(result.stopped_reason)
        # the failed-before-deploy cell ran again at the end of the queue and passed
        self.assertEqual(sorted(result.outcomes.values()), ["done", "done", "done"])
        self.assertEqual(len(result.ran), 3)
        self.assertEqual(pool.counts(), {"clean": 1})
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        first = ledger.entry("base/case-a/t1")
        self.assertEqual([a["outcome"] for a in first["attempts"]], ["interrupted", "done"])
        self.assertTrue(first["attempts"][0]["reason"].startswith("pre-deploy:"))

    async def test_agent_runner_error_is_retried_not_failed(self) -> None:
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:1], self.root / "pool")
        calls = {"n": 0}

        def hooks_factory(cell, run_dir, env):
            calls["n"] += 1
            if calls["n"] == 1:
                env.agent_env["FAKE_AGENT_MODE"] = "crash"    # codex "model at capacity" analogue
            return FakeHooks().lifecycle_hooks(), None

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=self._cell_env, pool=pool,
                                     concurrency=1, log=lambda m: None)
        self.assertIsNone(result.stopped_reason)
        self.assertEqual(sorted(result.outcomes.values()), ["done", "done", "done"])
        self.assertEqual(pool.counts(), {"clean": 1}, "teardown ran, so the account stays clean")
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        first = ledger.entry("base/case-a/t1")
        self.assertEqual([a["outcome"] for a in first["attempts"]], ["interrupted", "done"])
        self.assertIn("agent runner: AgentRunnerError", first["attempts"][0]["reason"])

    async def test_subscription_limit_moves_claude_cells_to_the_api_fallback(self) -> None:
        from harness.bench.routes import Fallback, RouteBook, route_status
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:1], self.root / "pool")
        seen = self.root / "seen.jsonl"

        def cell_env(cell, target):
            e = self._cell_env(cell, target)
            e.agent_env.update({"FAKE_AGENT_MODE": "limited", "FAKE_AGENT_SEEN": str(seen)})
            return e

        def hooks_factory(cell, run_dir, env):
            return FakeHooks().lifecycle_hooks(), None

        routes = RouteBook(self.root / "routes", Fallback("anthropic-api", "sk-ant-test"))
        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=cell_env, pool=pool, concurrency=1,
                                     log=lambda m: None, routes=routes)
        self.assertIsNone(result.stopped_reason, "a spent window no longer stops the batch")
        self.assertEqual(sorted(result.outcomes.values()), ["done", "done", "done"])
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        first = ledger.entry("base/case-a/t1")
        self.assertEqual([(a["outcome"], a.get("route")) for a in first["attempts"]],
                         [("interrupted", "subscription"), ("done", "api:anthropic-api")])
        self.assertIn("rate-limited (subscription)", first["attempts"][0]["reason"])
        # the other cells went straight to the fallback: only one cell paid for discovering the limit
        self.assertEqual([a.get("route") for a in ledger.entry("alt/case-a/t1")["attempts"]], ["api:anthropic-api"])
        self.assertEqual({json.loads(l)["key"] for l in seen.read_text().splitlines()}, {"sk-ant-test"})
        status = route_status(self.root / "routes", now=__import__("time").time())
        self.assertEqual(status["claude"]["mode"], "api")
        self.assertEqual(pool.counts(), {"clean": 1})

    async def test_without_a_fallback_limited_cells_wait_and_hold_no_account(self) -> None:
        from harness.bench.routes import RouteBook
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:1], self.root / "pool")

        def cell_env(cell, target):
            e = self._cell_env(cell, target)
            e.agent_env["FAKE_AGENT_MODE"] = "limited"
            return e

        routes = RouteBook(self.root / "routes", None)
        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=lambda c, r, e: (FakeHooks().lifecycle_hooks(), None),
                                     cell_env=cell_env, pool=pool, concurrency=1, log=lambda m: None, routes=routes)
        self.assertIsNone(result.stopped_reason)
        self.assertEqual(list(result.outcomes.values()), ["route-limited"], "one cell found the limit, the rest waited")
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        self.assertEqual(len(ledger.pending(spec.cells())), 3)
        self.assertEqual(pool.counts(), {"clean": 1})
        self.assertIsNone(routes.choose("claude"))
        self.assertIsNotNone(routes.choose("codex"), "codex keeps its own window")

    async def test_higher_order_arms_run_last(self) -> None:
        self.spec_path.write_text(SPEC.replace("  - name: base\n    trials: 2\n", "  - name: base\n    trials: 2\n    order: 1\n"))
        spec = self._spec()
        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=lambda c, r, e: (FakeHooks().lifecycle_hooks(), None),
                                     cell_env=self._cell_env, concurrency=1, log=lambda m: None)
        self.assertEqual(result.ran, ["alt/case-a/t1", "base/case-a/t1", "base/case-a/t2"])

    async def test_drain_finishes_running_cells_and_starts_no_new_one(self) -> None:
        import threading
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:1], self.root / "pool")
        drain = threading.Event()

        def hooks_factory(cell, run_dir, env):
            drain.set()                        # `bench stop --drain` lands while the first cell runs
            return FakeHooks().lifecycle_hooks(), None

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=hooks_factory, cell_env=self._cell_env, pool=pool,
                                     concurrency=1, log=lambda m: None, drain=drain)
        self.assertEqual(result.stopped_reason, "drained")
        self.assertEqual(result.outcomes, {"base/case-a/t1": "done"}, "the running cell finished and was scored")
        self.assertEqual(pool.counts(), {"clean": 1}, "nothing interrupted, the account stays clean")
        ledger = Ledger.open(result.batch_dir, batch="demo", spec_hash=spec.spec_hash, cells=spec.cells())
        self.assertEqual(len(ledger.pending(spec.cells())), 2)

    async def test_yield_to_stops_leasing_for_a_batch_that_goes_first(self) -> None:
        spec = self._spec()
        asks = []

        def yield_to():
            asks.append(1)
            return "paper-config-1 goes first (3 runnable cell(s) left)" if len(asks) > 1 else None

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=lambda c, r, e: (FakeHooks().lifecycle_hooks(), None),
                                     cell_env=self._cell_env, concurrency=1, log=lambda m: None, yield_to=yield_to)
        self.assertEqual(result.ran, ["base/case-a/t1"], "one cell ran, then the batch gave way")
        self.assertTrue(result.stopped_reason.startswith("yielded: paper-config-1 goes first"))

    async def test_drain_ends_a_wait_for_a_busy_pool(self) -> None:
        # 2026-09-24: a draining daemon whose workers waited for accounts lived on for 90 min
        import asyncio, threading
        spec = self._spec()
        pool = Pool(POOL_TARGETS[:1], self.root / "pool")
        other = pool.acquire("someone-else")                 # every account busy
        drain = threading.Event()
        loop = asyncio.get_running_loop()
        loop.call_later(0.5, drain.set)
        with _PathPrepend(self.root):
            result = await asyncio.wait_for(
                run_batch(spec, hooks_factory=lambda c, r, e: (FakeHooks().lifecycle_hooks(), None),
                          cell_env=self._cell_env, pool=pool, concurrency=1, log=lambda m: None, drain=drain), 30)
        self.assertEqual(result.ran, [])
        self.assertEqual(result.stopped_reason, "drained")
        pool.release(other, clean=True)
        self.assertEqual(pool.counts(), {"clean": 1})

    async def test_without_pool_leak_stops_batch(self) -> None:
        spec = self._spec()

        def leaky(cell, run_dir, env):
            return LeakingHooks().lifecycle_hooks(), None

        with _PathPrepend(self.root):
            result = await run_batch(spec, hooks_factory=leaky, cell_env=self._cell_env, log=lambda m: None)
        self.assertEqual(result.stopped_reason, "leak after base/case-a/t1")
        self.assertEqual(len(result.ran), 1)


class _PathPrepend:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def __enter__(self):
        self.old = os.environ["PATH"]
        os.environ["PATH"] = f"{self.directory}:{self.old}"

    def __exit__(self, *exc):
        os.environ["PATH"] = self.old


if __name__ == "__main__":
    unittest.main()
