from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from harness.runtime.app import _command_hook, load_runtime


class RuntimeConfigLoaderTests(unittest.TestCase):
    def write_config(self, root: Path, values: dict) -> Path:
        path = root / "runtime.json"
        path.write_text(json.dumps(values))
        return path

    def test_unscoped_local_config_parses_snapshot_matcher_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "d.py"
            source.write_text(
                "from harness.runtime import distract\n"
                "@distract(role='r', responsibility='x', intent='y', "
                "predicate=lambda snapshot: True)\n"
                "def run(snapshot):\n    pass\n"
            )
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            path = self.write_config(
                root,
                {
                    "run_id": "run",
                    "run_dir": "artifacts/run",
                    "allow_unscoped_credentials": True,
                    "distractors": [
                        {
                            "distractor_id": "d1",
                            "source": "d.py",
                            "sha256": digest,
                            "timeout": 3,
                        }
                    ],
                    "triggers": [
                        {
                            "trigger_id": "t1",
                            "matcher": {
                                "predicates": [
                                    {
                                        "path": "/resources/aws_subnet/web",
                                        "op": "exists",
                                    }
                                ],
                            },
                            "distractor_ids": ["d1"],
                            "occurrence": 2,
                            "required": False,
                            "release": "after_completed",
                        }
                    ],
                },
            )
            coordinator = load_runtime(path)
            self.assertEqual(coordinator.run_dir.resolve(), (root / "artifacts/run").resolve())
            self.assertEqual(coordinator.config.distractors["d1"].sha256, digest)
            trigger = coordinator.config.triggers[0]
            self.assertEqual(trigger.occurrence, 2)
            self.assertFalse(trigger.required)
            self.assertEqual(trigger.release, "after_completed")
            self.assertEqual(trigger.matcher.predicates[0].op, "exists")

    def test_real_config_requires_every_explicit_lifecycle_hook(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = self.write_config(
                Path(temp),
                {"run_id": "run", "run_dir": "run", "lifecycle": {}},
            )
            with self.assertRaisesRegex(ValueError, "lifecycle hooks"):
                load_runtime(path)

    def test_duplicate_and_missing_distractor_sources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "d.py"
            source.write_text("pass\n")
            base = {
                "run_id": "run",
                "run_dir": "run",
                "allow_unscoped_credentials": True,
            }
            duplicate = {
                **base,
                "distractors": [
                    {"distractor_id": "d", "source": "d.py"},
                    {"distractor_id": "d", "source": "d.py"},
                ],
            }
            with self.assertRaisesRegex(ValueError, "duplicate distractor_id"):
                load_runtime(self.write_config(root, duplicate))

            missing = {
                **base,
                "distractors": [{"distractor_id": "d", "source": "missing.py"}],
            }
            with self.assertRaisesRegex(ValueError, "missing distractor source"):
                load_runtime(self.write_config(root, missing))


class LifecycleCommandHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_plain_text_and_empty_stdout_are_normalized(self) -> None:
        cases = (
            ("import json; print(json.dumps({'verdict':'pass'}))", {"verdict": "pass"}),
            ("print('plain')", {"exit_code": 0, "stdout": "plain"}),
            ("pass", {"exit_code": 0}),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                hook = _command_hook([sys.executable, "-c", source], 5)
                self.assertEqual(await hook(), expected)

    async def test_nonzero_exit_and_timeout_raise(self) -> None:
        failing = _command_hook(
            [sys.executable, "-c", "import sys; print('bad', file=sys.stderr); sys.exit(7)"],
            5,
        )
        with self.assertRaisesRegex(RuntimeError, "bad"):
            await failing()

        timeout = _command_hook(
            [sys.executable, "-c", "import time; time.sleep(2)"], 0.05
        )
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            await timeout()


if __name__ == "__main__":
    unittest.main()
