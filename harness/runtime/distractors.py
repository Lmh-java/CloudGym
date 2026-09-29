"""Concurrent launch and lifecycle tracking for frozen SDK distractors."""

from __future__ import annotations

import time

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .controller import EventController
from .events import ApiEvent, SnapshotObservation
from .workers import SdkSubmissionRunner


@dataclass(frozen=True)
class DistractorDefinition:
    distractor_id: str
    source_path: Path
    sha256: str | None = None
    role_arn: str | None = None
    environment: Mapping[str, str] = field(default_factory=dict)
    timeout: float = 120.0


STDERR_TAIL_CHARS = 800


def stderr_tail(stderr: str | None, limit: int = STDERR_TAIL_CHARS) -> str:
    """The last ``limit`` characters of a program's stderr: the exception line and the
    frames that led to it, which is what a reader needs to see why a norm never landed."""
    text = (stderr or "").rstrip()
    return text if len(text) <= limit else "…" + text[-limit:]


class DistractorScheduler:
    def __init__(
        self,
        *,
        run_id: str,
        run_dir: Path,
        controller: EventController,
        definitions: Mapping[str, DistractorDefinition],
        base_env: Mapping[str, str],
        startup_timeout: float = 45.0,   # spawning python + boto3 under memory pressure took >10 s (2026-09-10)
    ):
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.controller = controller
        self.definitions = dict(definitions)
        self.base_env = dict(base_env)
        self.startup_timeout = startup_timeout
        self._firing = 0
        # Per distractor, one entry per firing: what the frozen program did.
        # A program that fails is an outcome, not a harness error — losing a
        # write race is realistic interference — and the oracle reads these
        # to judge the agent only on norms that were actually exercised.
        self.outcomes: dict[str, list[dict[str, Any]]] = {d: [] for d in self.definitions}

    def summary(self) -> dict[str, dict[str, Any]]:
        """Per-distractor record for the oracle (``input.distractors``) and result.json.

        ``status`` is ``succeeded`` when at least one firing ran its program to
        completion, ``failed`` when every firing failed, ``not-fired`` when no
        trigger ever matched. Oracles gate each distractor's norm on
        ``succeeded``: a norm that never landed is not held against the agent.
        """
        summary: dict[str, dict[str, Any]] = {}
        for distractor_id, outcomes in self.outcomes.items():
            succeeded = [o for o in outcomes if o["status"] == "succeeded"]
            status = "succeeded" if succeeded else ("failed" if outcomes else "not-fired")
            summary[distractor_id] = {
                "status": status,
                "fired": len(outcomes),
                "succeeded": len(succeeded),
                "result": succeeded[-1]["result"] if succeeded else None,
                "outcomes": list(outcomes),
            }
        return summary

    async def start_many(
        self, distractor_ids: tuple[str, ...], observation: SnapshotObservation | ApiEvent
    ) -> list[asyncio.Task[None]]:
        unknown = sorted(set(distractor_ids) - self.definitions.keys())
        if unknown:
            raise KeyError(f"unknown distractors: {unknown}")
        self._firing += 1
        trigger_dir = self.run_dir / "private" / "triggers"
        trigger_dir.mkdir(parents=True, exist_ok=True)
        trigger_dir.chmod(0o700)
        trigger_name = hashlib.sha256(observation.observation_id.encode()).hexdigest()[:24]
        trigger_path = trigger_dir / f"{trigger_name}.json"
        trigger_path.write_text(
            json.dumps(observation.to_dict(), ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        trigger_path.chmod(0o600)
        start_gate = asyncio.Event()
        started = {distractor_id: asyncio.Event() for distractor_id in distractor_ids}
        tasks = [
            asyncio.create_task(
                self._run_one(
                    self.definitions[distractor_id], observation, self._firing, start_gate,
                    started[distractor_id], trigger_path,
                ),
                name=f"distractor:{distractor_id}:{self._firing}",
            )
            for distractor_id in distractor_ids
        ]
        start_gate.set()
        try:
            await asyncio.wait_for(
                asyncio.gather(*(ready.wait() for ready in started.values())),
                timeout=self.startup_timeout,
            )
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return tasks

    async def _run_one(
        self,
        definition: DistractorDefinition,
        observation: SnapshotObservation | ApiEvent,
        firing: int,
        start_gate: asyncio.Event,
        started: asyncio.Event,
        trigger_path: Path,
    ) -> None:
        await start_gate.wait()
        source = definition.source_path.read_text(encoding="utf-8")
        actual_digest = hashlib.sha256(source.encode()).hexdigest()
        if definition.sha256 and actual_digest != definition.sha256:
            raise RuntimeError(
                f"frozen distractor {definition.distractor_id} hash changed"
            )
        submission_id = f"distractor-{definition.distractor_id}-{firing}"
        env = dict(self.base_env)
        env.update(definition.environment)
        env["CLOUDGYM_TRIGGER_SNAPSHOT_FILE"] = str(trigger_path)
        env["CLOUDGYM_TRIGGER_EVENT_FILE"] = str(trigger_path)
        env["CLOUDGYM_TRIGGER_SNAPSHOT_ID"] = observation.snapshot_id
        env["CLOUDGYM_TRIGGER_KIND"] = "api" if isinstance(observation, ApiEvent) else "snapshot"
        env["CLOUDGYM_FIRING"] = str(firing)      # 1-based launch number (refusal cycles)
        runner = SdkSubmissionRunner(
            run_id=self.run_id,
            run_dir=self.run_dir,
            controller=self.controller,
            timeout=definition.timeout,
            base_env=env,
        )

        async def process_started() -> None:
            await self.controller.record_runtime(
                "distractor.started",
                {
                    "distractor_id": definition.distractor_id,
                    "submission_id": submission_id,
                    "trigger_observation_id": observation.observation_id,
                    "trigger_snapshot_id": observation.snapshot_id,
                },
            )
            started.set()

        result = await runner.run(
            source,
            submission_id,
            on_process_started=process_started,
        )
        outcome = {
            "submission_id": submission_id,
            "firing": firing,
            "trigger_kind": env["CLOUDGYM_TRIGGER_KIND"],
            "status": result.status,
            "exit_code": result.exit_code,
            "result": result.result if result.status == "succeeded" else None,
            # When the program landed, on the same clock as the API journal: the consult
            # channel only credits the agent with observing a fingerprint fact if one of
            # its own responses carried it after this instant.
            "landed_ns": time.monotonic_ns(),
            "landed_s": round(self.controller.elapsed_s(), 3),
        }
        if result.status != "succeeded":
            # The tail of the program's stderr rides with the outcome so a failed norm
            # explains itself from distractor-summary.json and the journal: a program
            # that exited 1 in every run of a case for ten days went unread because the
            # only copy was a private evidence file nobody opened (2026-09-18).
            outcome["stderr_tail"] = stderr_tail(result.stderr)
        self.outcomes.setdefault(definition.distractor_id, []).append(outcome)
        if result.status != "succeeded":
            await self.controller.record_runtime(
                "distractor.failed",
                {
                    "distractor_id": definition.distractor_id,
                    "submission_id": submission_id,
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "stderr_tail": outcome["stderr_tail"],
                },
            )
            return
        await self.controller.record_runtime(
            "distractor.completed",
            {
                "distractor_id": definition.distractor_id,
                "submission_id": submission_id,
            },
        )
