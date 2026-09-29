"""A distractor with two triggers (snapshot predicate + api) launches once."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from harness.runtime.controller import EventController
from harness.runtime.events import ActorKind, ApiEvent, ApiPhase
from harness.runtime.matcher import ApiMatcher, SnapshotMatcher, TriggerSpec
from harness.runtime.store import JsonlEventStore


def _main_call(op: str, phase: ApiPhase) -> ApiEvent:
    return ApiEvent(run_id="run", sequence=0, actor_id="main", actor_kind=ActorKind.MAIN,
                    call_id=f"c-{op}-{phase.value}", phase=phase, service="s3", operation=op, region="us-east-1")


class FireOnceTests(unittest.IsolatedAsyncioTestCase):
    def _triggers(self, fire_once: bool) -> tuple[TriggerSpec, TriggerSpec]:
        meta = {"fire_once": fire_once}
        return (
            TriggerSpec(trigger_id="d1", distractor_ids=("d1",), metadata=meta,
                        matcher=SnapshotMatcher(predicates=(lambda s: bool(s["resources"].get("tagged")),))),
            TriggerSpec(trigger_id="d1:api", distractor_ids=("d1",), metadata=meta,
                        matcher=ApiMatcher("s3", "PutBucketTagging", phase="after_success")),
        )

    async def _run(self, fire_once: bool) -> list[tuple[str, ...]]:
        launches: list[tuple[str, ...]] = []

        async def starter(ids, observation):
            launches.append(ids)
            return [asyncio.create_task(asyncio.sleep(0))]

        with tempfile.TemporaryDirectory() as tmp:
            store = JsonlEventStore(Path(tmp) / "events.jsonl")
            controller = EventController("run", store, triggers=self._triggers(fire_once), distractor_starter=starter)
            await controller.observe_snapshot({"resources": {}}, snapshot_id="S0", initial=True)
            await controller.publish_api(_main_call("PutBucketTagging", ApiPhase.AFTER_SUCCESS))
            # A stale poll snapshot that still satisfies the predicate.
            await controller.observe_snapshot({"resources": {"tagged": True}}, snapshot_id="poll-1")
            await controller.finish(timeout=1)
            store.close()
        return launches

    async def test_fire_once_suppresses_second_trigger(self) -> None:
        self.assertEqual(await self._run(fire_once=True), [("d1",)])

    async def test_fire_once_false_allows_each_trigger(self) -> None:
        self.assertEqual(await self._run(fire_once=False), [("d1",), ("d1",)])


if __name__ == "__main__":
    unittest.main()


class RefusalCycleTests(unittest.IsolatedAsyncioTestCase):
    """max_fires=K: the trigger that launched the distractor re-fires on each later match, K times."""

    async def _run(self, max_fires: int, matches: int) -> list[tuple[str, ...]]:
        launches: list[tuple[str, ...]] = []

        async def starter(ids, observation):
            launches.append(ids)
            return [asyncio.create_task(asyncio.sleep(0))]

        meta = {"fire_once": True, "max_fires": max_fires}
        triggers = (
            TriggerSpec(trigger_id="d1", distractor_ids=("d1",), metadata=meta,
                        matcher=SnapshotMatcher(predicates=(lambda s: bool(s["resources"].get("tagged")),))),
            TriggerSpec(trigger_id="d1:api", distractor_ids=("d1",), metadata=meta,
                        matcher=ApiMatcher("dynamodb", "UpdateTable", phase="before")),
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonlEventStore(Path(tmp) / "events.jsonl")
            controller = EventController("run", store, triggers=triggers, distractor_starter=starter)
            await controller.observe_snapshot({"resources": {}}, snapshot_id="S0", initial=True)
            for _ in range(matches):
                await controller.publish_api(ApiEvent(
                    run_id="run", sequence=0, actor_id="main", actor_kind=ActorKind.MAIN, call_id="c",
                    phase=ApiPhase.BEFORE, service="dynamodb", operation="UpdateTable", region="us-east-1"))
                # a poll snapshot satisfying the predicate must never launch a second copy
                await controller.observe_snapshot({"resources": {"tagged": True}}, snapshot_id="poll")
            await controller.finish(timeout=1)
            store.close()
        return launches

    async def test_refires_on_each_reissue_up_to_the_limit(self) -> None:
        self.assertEqual(len(await self._run(max_fires=3, matches=5)), 3)
        self.assertEqual(len(await self._run(max_fires=1, matches=5)), 1)
        self.assertEqual(len(await self._run(max_fires=2, matches=1)), 1)
