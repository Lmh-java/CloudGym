from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from harness.runtime.controller import EventController
from harness.runtime.distractors import DistractorDefinition, DistractorScheduler
from harness.runtime.events import SnapshotObservation
from harness.runtime.store import JsonlEventStore


class DistractorSchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_distractor_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "private").mkdir()
            store = JsonlEventStore(root / "events.jsonl")
            controller = EventController("run", store)
            scheduler = DistractorScheduler(
                run_id="run",
                run_dir=root,
                controller=controller,
                definitions={},
                base_env={},
            )
            observation = SnapshotObservation.create(
                "run", 1, {"resources": {"ready": True}}, snapshot_id="S1"
            )
            with self.assertRaisesRegex(KeyError, "unknown distractors"):
                await scheduler.start_many(("missing",), observation)
            store.close()

    async def test_start_barrier_releases_before_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "private" / "distractor-runs").mkdir(parents=True)
            sources = {}
            for distractor_id in ("d1", "d2"):
                path = root / f"{distractor_id}.py"
                path.write_text("import time\ntime.sleep(0.4)\n")
                sources[distractor_id] = DistractorDefinition(distractor_id, path)

            store = JsonlEventStore(root / "events.jsonl")
            controller = EventController("run", store)
            scheduler = DistractorScheduler(
                run_id="run",
                run_dir=root,
                controller=controller,
                definitions=sources,
                base_env={},
                startup_timeout=2,
            )
            observation = SnapshotObservation.create(
                "run", 1, {"resources": {"ready": True}}, snapshot_id="S1"
            )
            tasks = await scheduler.start_many(("d1", "d2"), observation)
            self.assertTrue(all(not task.done() for task in tasks))
            records = [
                json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()
            ]
            started = [record for record in records if record["kind"] == "distractor.started"]
            self.assertEqual(len(started), 2)
            trigger_files = list((root / "private" / "triggers").glob("*.json"))
            self.assertEqual(len(trigger_files), 1)
            self.assertEqual(
                json.loads(trigger_files[0].read_text())["observation_id"],
                observation.observation_id,
            )
            await asyncio.gather(*tasks)
            store.close()

if __name__ == "__main__":
    unittest.main()


class DistractDecoratorPairingTests(unittest.TestCase):
    def test_resolution_stands_alone_and_a_subject_needs_one(self) -> None:
        from harness.runtime.decorators import distract

        # A reply with no concept words: reached through the fingerprint run() returns.
        decorated = distract(role="r", responsibility="s", intent="i", predicate=lambda s: False,
                             resolution="the block stays theirs")(lambda: {"fingerprint": ["subnet-1"]})
        self.assertEqual(decorated.__cloudgym_distractor__.subject, ())
        with self.assertRaises(ValueError):
            distract(role="r", responsibility="s", intent="i", predicate=lambda s: False,
                     subject=("address space",))

    def test_occurrence_two_requires_predicate_fallback(self) -> None:
        from harness.runtime.decorators import distract, on_api

        with self.assertRaises(ValueError):
            distract(role="r", responsibility="s", intent="i",
                     api=on_api("s3", "PutBucketTagging", occurrence=2))
        # paired with a predicate the same trigger is accepted
        decorated = distract(role="r", responsibility="s", intent="i",
                             predicate=lambda snapshot: False,
                             api=on_api("s3", "PutBucketTagging", occurrence=2))(lambda: {})
        metadata = decorated.__cloudgym_distractor__
        self.assertEqual(metadata.api.occurrence, 2)
        # occurrence=1 alone stays valid without a predicate
        distract(role="r", responsibility="s", intent="i",
                 api=on_api("s3", "PutBucketTagging"))(lambda: {})
