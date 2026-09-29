"""The fail-closed event controller and exactly-once trigger engine."""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable
from typing import Any, Mapping

from .events import ActorKind, ApiEvent, ApiPhase, SnapshotObservation, runtime_record, sanitize_public
from .invariants import InvariantEvent, InvariantMonitor, InvariantSpec
from .matcher import ApiMatcher, SnapshotMatcher, TriggerSpec
from .store import JsonlEventStore

TriggerSource = SnapshotObservation | ApiEvent
DistractorStarter = Callable[
    [tuple[str, ...], TriggerSource], Awaitable[list[asyncio.Task[Any]]]
]
MutationObserver = Callable[[ApiEvent], Awaitable[None]]


class EventControllerError(RuntimeError):
    pass


class EventController:
    def __init__(
        self,
        run_id: str,
        store: JsonlEventStore,
        *,
        triggers: Iterable[TriggerSpec] = (),
        invariants: Iterable[InvariantSpec] = (),
        distractor_starter: DistractorStarter | None = None,
        on_main_mutation: MutationObserver | None = None,
    ):
        self.run_id = run_id
        self.store = store
        self.triggers = tuple(triggers)
        self.invariants = InvariantMonitor(tuple(invariants))
        self.distractor_starter = distractor_starter
        # Called with every successful mutating main-actor call while the proxy
        # still holds its response; the coordinator uses it to observe a snapshot
        # right away so snapshot-predicate distractors fire (and, with
        # release=after_completed, land) before the agent sees the call succeed.
        self.on_main_mutation = on_main_mutation
        self._sequence = 0
        self._lock = asyncio.Lock()
        self._match_counts: dict[str, int] = defaultdict(int)
        self._fired: set[str] = set()
        # Distractors already launched. A distractor usually declares two
        # triggers (snapshot predicate + api); with ``fire_once`` (the default)
        # the second one must not launch it again — a stale poll snapshot taken
        # before the first firing's write landed would otherwise re-run a
        # replace-all distractor on top of the agent's re-merge.
        self._fired_distractors: set[str] = set()
        # Refusal cycles: launches so far per distractor, and the trigger that launched it first
        # (only that trigger re-fires, on each later match, until ``max_fires``).
        self._fire_counts: dict[str, int] = defaultdict(int)
        self._first_trigger: dict[str, str] = {}
        self._last_snapshot: Mapping[str, Any] | None = None
        self._background: set[asyncio.Task[Any]] = set()
        self.invalid_reason: str | None = None
        self.accepting = True
        self._started_monotonic_ns = time.monotonic_ns()
        # Terminal phases of distractor API calls, for the agent-facing
        # ``changes`` tool (awareness levels observed/disclosed).
        self._distractor_activity: list[ApiEvent] = []
        # The agent's own completed calls: (monotonic_ns, call_id). The proxy keeps every
        # response body under private/api/<call_id>.res; this index says which of those the
        # agent received after a given instant (see RuntimeCoordinator._observed_by_agent).
        self._main_responses: list[tuple[int, str]] = []

    async def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    async def record_runtime(self, kind: str, data: Mapping[str, Any]) -> dict[str, Any]:
        async with self._lock:
            sequence = await self._next_sequence()
            record = runtime_record(self.run_id, sequence, kind, data)
            self.store.append(record)
            return record

    async def observe_snapshot(
        self,
        snapshot: Mapping[str, Any],
        *,
        snapshot_id: str,
        initial: bool = False,
    ) -> SnapshotObservation:
        """Persist a normalized observation and evaluate snapshot triggers."""
        if not self.accepting:
            raise EventControllerError("event controller is no longer accepting snapshots")
        matched: list[TriggerSpec] = []
        invariant_events: list[InvariantEvent] = []
        try:
            async with self._lock:
                sequence = await self._next_sequence()
                observation = SnapshotObservation.create(
                    self.run_id,
                    sequence,
                    snapshot,
                    snapshot_id=snapshot_id,
                    initial=initial,
                )
                self.store.append(observation.to_dict())
                previous = self._last_snapshot
                self._last_snapshot = observation.snapshot
                # Invariants are checked on every observation, S0 included,
                # and are recorded in sequence right after the observation
                # so the event log shows which snapshot broke them.
                invariant_events = self.invariants.observe(
                    observation.snapshot,
                    observation_id=observation.observation_id,
                    snapshot_id=observation.snapshot_id,
                    sequence=sequence,
                    initial=initial,
                )
                for event in invariant_events:
                    self.store.append(runtime_record(
                        self.run_id, await self._next_sequence(), event.kind, event.data
                    ))
                if not initial:
                    for trigger in self.triggers:
                        if not self._eligible(trigger):
                            continue
                        if not isinstance(trigger.matcher, SnapshotMatcher):
                            continue
                        if trigger.matcher.matches(observation.snapshot, previous):
                            self._count_match(trigger, matched)
        except Exception as exc:
            self.invalid_reason = f"snapshot processing failed: {exc}"
            raise EventControllerError(self.invalid_reason) from exc
        # A broken monitor or an S0 that already violates an invariant makes
        # the run unscorable; an ordinary violation is evidence, not an error.
        monitor_reason = self.invariants.invalid_reason
        if monitor_reason and invariant_events:
            self.invalid_reason = self.invalid_reason or monitor_reason
        if matched:
            await self._fire(matched, observation)
        return observation

    def _limit(self, trigger: TriggerSpec) -> float:
        limit = trigger.metadata.get("max_fires")
        if limit is not None:
            return float(limit)
        return 1.0 if trigger.metadata.get("fire_once", True) else float("inf")

    def _eligible(self, trigger: TriggerSpec) -> bool:
        limit = self._limit(trigger)
        if trigger.trigger_id in self._fired:
            # A trigger that already fired re-fires only as the distractor's first trigger,
            # and only while launches remain (refusal cycles).
            return limit > 1 and all(
                self._first_trigger.get(d) == trigger.trigger_id and self._fire_counts[d] < limit
                for d in trigger.distractor_ids)
        if any(d in self._fired_distractors for d in trigger.distractor_ids):
            # Another trigger launched this distractor already.
            return not trigger.metadata.get("fire_once", True) and limit == float("inf")
        return True

    def _count_match(self, trigger: TriggerSpec, matched: list[TriggerSpec]) -> None:
        if trigger.trigger_id in self._fired:
            matched.append(trigger)           # a re-fire: every later match launches again
            return
        self._match_counts[trigger.trigger_id] += 1
        if self._match_counts[trigger.trigger_id] == trigger.occurrence:
            self._fired.add(trigger.trigger_id)
            matched.append(trigger)

    async def publish_api(self, event: ApiEvent) -> ApiEvent:
        """Journal one API-call phase; returning is the permit to proceed.

        Every main-actor phase is offered to the API triggers; each matcher
        accepts only the phase it declares (``before``, ``after_success`` or
        ``after_error``). When one fires, this call blocks until the
        distractors have started (or completed, per ``release``) — the proxy
        holds the request (``before``) or the response (``after_*``)
        meanwhile, so with ``after_completed`` an ``after_success`` distractor's
        write lands before the agent's own call returns.

        A successful mutating main-actor call additionally invokes
        ``on_main_mutation`` (still inside the hold) so snapshot predicates are
        evaluated against the state the call just produced instead of waiting
        for the next poll tick.
        """
        if not self.accepting:
            raise EventControllerError("event controller is no longer accepting API events")
        matched: list[TriggerSpec] = []
        try:
            async with self._lock:
                sequence = await self._next_sequence()
                event = dataclasses.replace(event, sequence=sequence)
                self.store.append(event.to_dict())
                if event.actor_kind is ActorKind.DISTRACTOR and event.phase is not ApiPhase.BEFORE:
                    self._distractor_activity.append(event)
                if event.actor_kind is ActorKind.MAIN and event.phase is ApiPhase.AFTER_SUCCESS:
                    self._main_responses.append((event.monotonic_ns, event.call_id))
                if event.actor_kind is ActorKind.MAIN:
                    for trigger in self.triggers:
                        if not self._eligible(trigger):
                            continue
                        if not isinstance(trigger.matcher, ApiMatcher):
                            continue
                        if trigger.matcher.matches(event):
                            self._count_match(trigger, matched)
        except Exception as exc:
            self.invalid_reason = f"api event processing failed: {exc}"
            raise EventControllerError(self.invalid_reason) from exc
        if matched:
            await self._fire(matched, event)
        if (self.on_main_mutation is not None and event.actor_kind is ActorKind.MAIN
                and event.phase is ApiPhase.AFTER_SUCCESS and event.mutating):
            try:
                await self.on_main_mutation(event)
            except EventControllerError:
                raise
            except Exception as exc:
                self.invalid_reason = self.invalid_reason or f"post-mutation snapshot failed: {exc}"
                await self.record_runtime("snapshot.observer_failed", {
                    "error": str(exc), "after_call_id": event.call_id,
                })
        return event

    async def _fire(self, triggers: list[TriggerSpec], observation: TriggerSource) -> None:
        if self.distractor_starter is None:
            self.invalid_reason = "trigger matched but no distractor starter is configured"
            raise EventControllerError(self.invalid_reason)

        distractors: list[str] = []
        for trigger in triggers:
            for distractor_id in trigger.distractor_ids:
                if distractor_id not in distractors:
                    distractors.append(distractor_id)
        self._fired_distractors.update(distractors)
        for trigger in triggers:
            for distractor_id in trigger.distractor_ids:
                self._fire_counts[distractor_id] += 1
                self._first_trigger.setdefault(distractor_id, trigger.trigger_id)
        await self.record_runtime(
            "trigger.matched",
            {
                "observation_id": observation.observation_id,
                "snapshot_id": observation.snapshot_id,
                "trigger_kind": triggers[0].kind,
                "trigger_ids": [trigger.trigger_id for trigger in triggers],
                "distractor_ids": distractors,
            },
        )
        try:
            tasks = await self.distractor_starter(tuple(distractors), observation)
        except Exception as exc:
            # str(TimeoutError()) is empty; always name the exception type.
            self.invalid_reason = f"distractor startup failed: {type(exc).__name__}: {exc}".rstrip(": ")
            await self.record_runtime("trigger.failed", {
                "observation_id": observation.observation_id,
                "snapshot_id": observation.snapshot_id,
                "error": str(exc),
            })
            raise EventControllerError(self.invalid_reason) from exc

        for task in tasks:
            self._background.add(task)
            task.add_done_callback(self._background.discard)
            task.add_done_callback(self._observe_background_failure)

        if any(trigger.release == "after_completed" for trigger in triggers):
            results = await asyncio.gather(*tasks, return_exceptions=True)
            failures = [result for result in results if isinstance(result, BaseException)]
            if failures:
                self.invalid_reason = f"distractor failed before main release: {failures[0]}"
                raise EventControllerError(self.invalid_reason)

    def _observe_background_failure(self, task: asyncio.Task[Any]) -> None:
        if task.cancelled():
            self.invalid_reason = self.invalid_reason or "distractor task was cancelled"
            return
        error = task.exception()
        if error is not None:
            self.invalid_reason = self.invalid_reason or f"distractor task failed: {error}"

    async def finish(self, timeout: float) -> None:
        pending = list(self._background)
        if pending:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True), timeout=timeout
                )
            except TimeoutError as exc:
                for task in pending:
                    task.cancel()
                self.invalid_reason = "distractor drain timed out"
                raise EventControllerError(self.invalid_reason) from exc
            failures = [result for result in results if isinstance(result, BaseException)]
            if failures:
                self.invalid_reason = self.invalid_reason or f"distractor failed: {failures[0]}"
        required_unfired = [
            trigger.trigger_id
            for trigger in self.triggers
            if trigger.required and trigger.trigger_id not in self._fired
        ]
        if required_unfired:
            self.invalid_reason = self.invalid_reason or (
                f"required triggers did not fire: {sorted(required_unfired)}"
            )
        self.accepting = False
        invariants = self.invariants.summary()
        await self.record_runtime(
            "run.event_controller_finished",
            {"invalid_reason": self.invalid_reason, "fired_triggers": sorted(self._fired),
             "violated_invariants": invariants["violated"],
             "unrestored_invariants": invariants["unrestored"]},
        )

    def distractor_activity(self) -> list[dict[str, Any]]:
        """What other principals have done, as observed: one entry per completed call."""
        items = []
        for event in self._distractor_activity:
            outcome = event.outcome or {}
            items.append({
                "t_s": round((event.monotonic_ns - self._started_monotonic_ns) / 1e9, 1),
                "principal": event.actor_id,
                "service": event.service,
                "operation": event.operation,
                "parameters": sanitize_public(event.parameters),
                "status": outcome.get("status") if event.phase is ApiPhase.AFTER_SUCCESS else "error",
            })
        return items

    def touched_by(self, principal: str) -> set[str]:
        """Identifiers the principal's successful writes carried: parameters and outcomes of
        its mutating calls. What it merely read is not "touched" — a lister that returns
        the agent's own zone must not make the agent's every question reach it."""
        from .consult import harvest_identifiers

        found: set[str] = set()
        for event in self._distractor_activity:
            if event.actor_id != principal or event.phase is not ApiPhase.AFTER_SUCCESS or not event.mutating:
                continue
            found |= harvest_identifiers(event.parameters)
            found |= harvest_identifiers(event.outcome or {})
        return found

    def elapsed_s(self) -> float:
        return (time.monotonic_ns() - self._started_monotonic_ns) / 1e9

    def main_responses_since(self, monotonic_ns: int) -> list[str]:
        """Call ids of the agent's successful calls whose response arrived at or after
        ``monotonic_ns``, oldest first."""
        return [call_id for at, call_id in self._main_responses if at >= monotonic_ns]

    def roster(self, *, private: bool = False) -> list[dict[str, Any]]:
        """Other principals with access, from the distractors' declared metadata.

        ``private`` additionally returns each principal's declared ``resolution`` and
        ``subject``. Those are what ``consult`` awareness hands out, one principal at a
        time and only once their program has landed, so the default must never include
        them: the `changes` tool returns this roster verbatim, and at ``observed`` it is
        available from the first turn.
        """
        seen: dict[str, dict[str, Any]] = {}
        for trigger in self.triggers:
            for distractor_id in trigger.distractor_ids:
                meta = trigger.metadata or {}
                entry = {
                    "principal": distractor_id,
                    "role": meta.get("role"),
                    "responsibility": meta.get("responsibility"),
                    "intent": meta.get("intent"),
                }
                if private:
                    entry["resolution"] = meta.get("resolution", "")
                    entry["subject"] = meta.get("subject", [])
                seen.setdefault(distractor_id, entry)
        return list(seen.values())

    def invariant_summary(self) -> dict[str, Any]:
        return self.invariants.summary()

    def trigger_summary(self) -> dict[str, Any]:
        return {
            "fired": sorted(self._fired),
            "fired_kinds": {t.trigger_id: t.kind for t in self.triggers if t.trigger_id in self._fired},
            "match_counts": dict(sorted(self._match_counts.items())),
            "required_unfired": sorted(
                trigger.trigger_id
                for trigger in self.triggers
                if trigger.required and trigger.trigger_id not in self._fired
            ),
            "invalid_reason": self.invalid_reason,
        }
