"""Per-run coordinator shared by MCP tools and local integration tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import dataclass, field
from importlib.metadata import version
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

import boto3
from ..aws_env import scrubbed_environment
from .consult import ConsultChannel, harvest_identifiers
from .controller import EventController
from .distractors import DistractorDefinition, DistractorScheduler
from .events import ApiEvent, CANONICALIZER_VERSION, sanitize_public
from .invariants import InvariantSpec
from .matcher import TriggerSpec
from .store import JsonlEventStore

LifecycleHook = Callable[[], Awaitable[Mapping[str, Any] | None]]


async def _noop_hook() -> Mapping[str, Any] | None:
    return None


@dataclass
class LifecycleHooks:
    deploy_initial: LifecycleHook = _noop_hook
    verify_initial: LifecycleHook = _noop_hook
    observe_snapshot: LifecycleHook = _noop_hook
    capture_final: LifecycleHook = _noop_hook
    evaluate_oracle: LifecycleHook = _noop_hook
    reset: LifecycleHook = _noop_hook
    destroy: LifecycleHook = _noop_hook
    leak_check: LifecycleHook = _noop_hook


@dataclass
class RuntimeConfig:
    run_id: str
    run_dir: Path
    region: str = "us-east-1"
    triggers: tuple[TriggerSpec, ...] = ()
    invariants: tuple[InvariantSpec, ...] = ()
    distractors: Mapping[str, DistractorDefinition] = field(default_factory=dict)
    input_hashes: Mapping[str, str] = field(default_factory=dict)
    main_role_arn: str | None = None
    allow_unscoped_credentials: bool = False
    distractor_environment: Mapping[str, str] = field(default_factory=dict)
    lifecycle_timeout: float = 900.0
    distractor_drain_timeout: float = 180.0
    snapshot_poll_interval: float = 5.0
    fsync_events: bool = False
    # Terms the requester's own words already carry (see consult.excluded_terms); a
    # principal is never reached through them.
    consult_excluded_terms: tuple[str, ...] = ()


class RuntimeCoordinator:
    def __init__(self, config: RuntimeConfig, *, hooks: LifecycleHooks | None = None):
        self.config = config
        self.hooks = hooks or LifecycleHooks()
        self.run_dir = Path(config.run_dir)
        self.store: JsonlEventStore | None = None
        self.controller: EventController | None = None
        self._distractor_source_hashes: dict[str, str] = {}
        self._submission_lock = asyncio.Lock()
        self._observe_lock = asyncio.Lock()
        self._started = False
        self._finished = False
        self._snapshot_task: asyncio.Task[None] | None = None
        self._snapshot_counter = 0
        self._finish_result: dict[str, Any] | None = None
        self.scheduler: DistractorScheduler | None = None
        self._finish_task: asyncio.Task[dict[str, Any]] | None = None
        self.consult_channel: ConsultChannel | None = None
        self._s0_terms: frozenset[str] = frozenset()
        self._observed_cache: dict[str, set[str]] = {}

    async def start(self) -> None:
        if self._started:
            raise RuntimeError("runtime already started")
        if (self.run_dir / "run.json").exists():
            raise RuntimeError(f"run directory already holds a run: {self.run_dir}")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for relative in ("private", "private/distractor-runs"):
            directory = self.run_dir / relative
            directory.mkdir(exist_ok=True)
            directory.chmod(0o700)
        self._write_run_metadata("starting")
        try:
            self._validate_role_configuration()
            deploy = await self.hooks.deploy_initial()
            verify = await self.hooks.verify_initial()

            self.store = JsonlEventStore(
                self.run_dir / "events.jsonl", fsync=self.config.fsync_events
            )
            self.controller = EventController(
                self.config.run_id,
                self.store,
                triggers=self.config.triggers,
                invariants=self.config.invariants,
                on_main_mutation=self._observe_after_mutation,
            )
            if isinstance(verify, Mapping) and isinstance(verify.get("snapshot"), Mapping):
                await self.controller.observe_snapshot(
                    verify["snapshot"],
                    snapshot_id=str(verify.get("snapshot_id", "S0")),
                    initial=True,
                )
                # What was already there is the requester's vocabulary, not evidence that
                # the agent noticed a principal: the seed VPC's id is in every question on
                # a VPC case. A principal that touches a seed resource is reached through
                # its concept subjects, never through that resource's identity.
                self._s0_terms = frozenset(t.lower() for t in harvest_identifiers(verify["snapshot"]))
            distractor_base = self._worker_base_environment()
            distractor_base.update(self.config.distractor_environment)
            resolved_distractors = await self._resolve_distractors()
            scheduler = DistractorScheduler(
                run_id=self.config.run_id,
                run_dir=self.run_dir,
                controller=self.controller,
                definitions=resolved_distractors,
                base_env=distractor_base,
            )
            self.controller.distractor_starter = scheduler.start_many
            self.scheduler = scheduler
            await self.controller.record_runtime(
                "run.started", {"deploy": deploy, "initial_verification": verify}
            )
            self._started = True
            self._snapshot_task = asyncio.create_task(
                self._snapshot_loop(), name=f"snapshot-observer:{self.config.run_id}"
            )
            self._write_run_metadata("running")
        except BaseException as exc:
            await self._cleanup_failed_start(exc)
            raise

    def _validate_role_configuration(self) -> None:
        trigger_ids = [trigger.trigger_id for trigger in self.config.triggers]
        if len(trigger_ids) != len(set(trigger_ids)):
            raise RuntimeError("trigger_id values must be unique")
        known_distractors = set(self.config.distractors)
        referenced_distractors = {
            distractor_id
            for trigger in self.config.triggers
            for distractor_id in trigger.distractor_ids
        }
        unknown = sorted(referenced_distractors - known_distractors)
        if unknown:
            raise RuntimeError(f"triggers reference unknown distractors: {unknown}")
        mismatched = sorted(
            key
            for key, definition in self.config.distractors.items()
            if key != definition.distractor_id
        )
        if mismatched:
            raise RuntimeError(f"distractor mapping keys do not match IDs: {mismatched}")
        if not self.config.allow_unscoped_credentials:
            missing_roles = sorted(
                key
                for key, definition in self.config.distractors.items()
                if not definition.role_arn
            )
            if missing_roles:
                raise RuntimeError(
                    f"every distractor requires a role_arn: {missing_roles}"
                )
            missing_hashes = sorted(
                key
                for key, definition in self.config.distractors.items()
                if not definition.sha256
            )
            if missing_hashes:
                raise RuntimeError(
                    f"every distractor requires a certified source sha256: {missing_hashes}"
                )
        role_arns = [
            definition.role_arn
            for definition in self.config.distractors.values()
            if definition.role_arn
        ]
        if len(role_arns) != len(set(role_arns)):
            raise RuntimeError("each distractor must use a distinct role ARN")

    async def _resolve_distractors(self) -> dict[str, DistractorDefinition]:
        resolved_distractors: dict[str, DistractorDefinition] = {}
        frozen_dir = self.run_dir / "private" / "distractors"
        frozen_dir.mkdir(mode=0o700)
        for distractor_id, definition in self.config.distractors.items():
            source = definition.source_path.read_bytes()
            digest = hashlib.sha256(source).hexdigest()
            if definition.sha256 and digest != definition.sha256:
                raise RuntimeError(
                    f"distractor {distractor_id} hash mismatch: "
                    f"expected {definition.sha256}, got {digest}"
                )
            frozen_source = frozen_dir / f"{distractor_id}.py"
            frozen_source.write_bytes(source)
            frozen_source.chmod(0o600)
            self._distractor_source_hashes[distractor_id] = digest
            environment = dict(definition.environment)
            if definition.role_arn:
                environment.update(
                    await asyncio.to_thread(
                        self._assume_role_environment,
                        definition.role_arn,
                        f"cloudgym-{self.config.run_id}-{distractor_id}",
                    )
                )
            resolved_distractors[distractor_id] = DistractorDefinition(
                distractor_id=definition.distractor_id,
                source_path=frozen_source,
                sha256=digest,
                role_arn=definition.role_arn,
                environment=environment,
                timeout=definition.timeout,
            )
        return resolved_distractors

    async def _cleanup_failed_start(self, exc: BaseException) -> None:
        cleanup: Mapping[str, Any] | None = None
        if self.controller is not None and self.store is not None:
            try:
                await self.controller.record_runtime(
                    "run.start_failed", {"error": f"{type(exc).__name__}: {exc}"}
                )
            except Exception:
                pass
        await self._stop_snapshot_observer()
        if self.store is not None:
            try:
                self.store.close()
            except Exception:
                pass
        cleanup, cleanup_errors = await self._run_cleanup(include_reset=False)
        self._finished = True
        self._write_run_metadata(
            "startup_failed",
            {
                "error": f"{type(exc).__name__}: {exc}",
                "cleanup": cleanup,
                "cleanup_errors": cleanup_errors,
            },
        )

    @staticmethod
    def _worker_base_environment() -> dict[str, str]:
        return scrubbed_environment()

    @staticmethod
    def _assume_role_environment(role_arn: str, session_name: str) -> dict[str, str]:
        response = boto3.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name[:64],
            DurationSeconds=3600,
        )
        credentials = response["Credentials"]
        return {
            "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
            "AWS_SESSION_TOKEN": credentials["SessionToken"],
        }

    @property
    def finished(self) -> bool:
        """True once finish() has been called or requested."""
        return self._finished or self._finish_task is not None

    async def finish(self) -> dict[str, Any]:
        """Evaluate and clean up; a second call returns the first call's result."""
        async with self._submission_lock:
            if self._finish_result is not None:
                return self._finish_result
            self._ensure_running()
            self._finished = True
            final_snapshot: Mapping[str, Any] | None = None
            oracle: Mapping[str, Any] | None = None
            cleanup: Mapping[str, Any] | None = None
            invariants: Mapping[str, Any] | None = None
            distractors: Mapping[str, Any] | None = None
            error: str | None = None
            try:
                await self._stop_snapshot_observer()
                # One last observation so a change the agent made just before
                # finishing can still trigger its distractors.
                await self._observe_once(label="final-observation")
                await self.controller.finish(self.config.distractor_drain_timeout)
                final_snapshot = await self.hooks.capture_final()
                # Persist the invariant and distractor records before the oracle
                # runs so the evaluate_oracle hook can feed them in as
                # ``input.invariants`` and ``input.distractors``.
                invariants = self._write_invariant_summary()
                distractors = self._write_distractor_summary()
                oracle = await self.hooks.evaluate_oracle()
                if not self.config.allow_unscoped_credentials:
                    if not isinstance(oracle, Mapping) or oracle.get("verdict") != "pass":
                        raise RuntimeError(
                            "oracle hook must return a JSON object with verdict='pass'"
                        )
            except Exception as exc:
                error = str(exc)
            finally:
                cleanup, cleanup_errors = await self._run_cleanup(include_reset=True)
                if cleanup_errors:
                    error = error or "; ".join(cleanup_errors)
                if invariants is None:
                    try:
                        invariants = self._write_invariant_summary()
                    except Exception as exc:
                        error = error or f"invariant summary persistence failed: {exc}"
                if distractors is None:
                    try:
                        distractors = self._write_distractor_summary()
                    except Exception as exc:
                        error = error or f"distractor summary persistence failed: {exc}"
                try:
                    self._write_consult_summary()
                except Exception as exc:
                    error = error or f"consult summary persistence failed: {exc}"
                try:
                    (self.run_dir / "trigger-summary.json").write_text(
                        json.dumps(
                            sanitize_public(self.controller.trigger_summary()),
                            indent=2,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                except Exception as exc:
                    error = error or f"trigger summary persistence failed: {exc}"
                try:
                    self.store.close()
                except Exception as exc:
                    error = error or f"event store shutdown failed: {exc}"
            status = "invalid" if error or self.controller.invalid_reason else "completed"
            self._write_run_metadata(
                status,
                {
                    "error": error or self.controller.invalid_reason,
                    "final_snapshot": final_snapshot,
                    "oracle": oracle,
                    "invariants": invariants,
                    "distractors": distractors,
                    "cleanup": cleanup,
                },
            )
            self._finish_result = {
                "run_id": self.config.run_id,
                "status": status,
                "error": error or self.controller.invalid_reason,
                "final_snapshot": final_snapshot,
                "oracle": oracle,
                "invariants": invariants,
                "distractors": distractors,
                "cleanup": cleanup,
            }
            return self._finish_result

    def consult(self, about: str = "", question: str = "", thread: str | None = None, *,
                require_landed: bool = True) -> dict[str, Any]:
        """Put a question to the other principals, or re-read a thread.

        The channel is created on first use with the level's gate. With ``require_landed``
        (the ``consult`` level) the channel routes in fingerprint mode: a principal answers
        only once its program has landed, only a question citing a fact the program
        returned as its ``fingerprint`` reaches it, and only if the agent's own journaled
        reads returned that fact after the landing. Without it (``consult_open``, the
        historical control) a principal is reached whenever asked, by an identifier its
        writes carried or by a declared concept subject. Routing and delivery are in
        :mod:`harness.runtime.consult`; replies accrue on threads, and what arrived on
        earlier threads is handed over with every call.
        """
        if self.consult_channel is None:
            self.consult_channel = ConsultChannel(
                principals=lambda: self.controller.roster(private=True) if self.controller else [],
                landed=lambda: {d for d, status in self._landed_distractors().items() if status == "succeeded"},
                touched=self._touched_by,
                clock=lambda: self.controller.elapsed_s() if self.controller else 0.0,
                require_landed=require_landed,
                excluded=set(self.config.consult_excluded_terms) | self._s0_terms,
                fingerprints=self._fingerprints_by if require_landed else None,
                observed=self._observed_by_agent if require_landed else None,
            )
        elif self.consult_channel.require_landed != require_landed:
            raise RuntimeError("the consult gate cannot change mid-run")
        return self.consult_channel.ask(about, question, thread)

    def _touched_by(self, principal: str) -> set[str]:
        """Identifiers the principal's program touched: what its ``run()`` returned as
        evidence (the zone it created, the store it wrote, the config it moved) plus what
        its journaled writes carried. The evidence dict is the reliable source — distractor
        calls are journaled without decoded parameters or bodies, so a program that wants a
        question naming its object to reach it returns that object's identifier."""
        from .consult import harvest_identifiers

        found = self.controller.touched_by(principal) if self.controller else set()
        summary = self.scheduler.summary() if self.scheduler else {}
        entry = summary.get(principal) or {}
        for outcome in entry.get("outcomes") or []:
            if (outcome or {}).get("status") == "succeeded":
                found |= harvest_identifiers((outcome or {}).get("result"))
        found |= harvest_identifiers(entry.get("result"))
        return found

    def _succeeded_outcomes(self, principal: str) -> list[dict[str, Any]]:
        summary = self.scheduler.summary() if self.scheduler else {}
        entry = summary.get(principal) or {}
        return [o for o in (entry.get("outcomes") or []) if (o or {}).get("status") == "succeeded"]

    def _fingerprints_by(self, principal: str) -> dict[str, str]:
        """The facts a principal's program declared as its fingerprint (``{said: seen}``):
        what is in the account only because it ran. Only these route at ``consult``."""
        from .consult import fingerprint_facts

        facts: dict[str, str] = {}
        for outcome in self._succeeded_outcomes(principal):
            facts.update(fingerprint_facts(outcome.get("result")))
        return facts

    def _observed_by_agent(self, principal: str, fact: str) -> bool:
        """Whether one of the agent's own responses, received after ``principal`` landed,
        carried ``fact``. The proxy stores every response body under private/api/<call_id>.res;
        the controller indexes the agent's calls by time. A numeric fact must sit in value
        position (after ``:``, ``=`` or ``>``), so a retention term of 731 is not found
        inside a timestamp. The lookup is cached once found — a fact read once stays read."""
        from .observation import responses_carrying

        cache = self._observed_cache.setdefault(principal, set())
        if fact in cache:
            return True
        if not self.controller:
            return False
        outcomes = self._succeeded_outcomes(principal)
        landed_ns = [o.get("landed_ns") for o in outcomes if isinstance(o.get("landed_ns"), int)]
        if not landed_ns:
            return False
        hit = responses_carrying(self.run_dir / "private" / "api",
                                 self.controller.main_responses_since(min(landed_ns)), fact)
        if hit is None:
            return False
        cache.add(fact)
        return True

    def _landed_distractors(self) -> dict[str, str]:
        summary = self.scheduler.summary() if self.scheduler else {}
        return {distractor_id: (entry or {}).get("status", "not-fired")
                for distractor_id, entry in summary.items()}

    def _write_consult_summary(self) -> dict[str, Any] | None:
        """Persist ``consult-summary.json``: every thread, reply and what was left unread."""
        if self.consult_channel is None:
            return None
        summary = sanitize_public(self.consult_channel.summary())
        (self.run_dir / "consult-summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        return summary

    def _write_distractor_summary(self) -> dict[str, Any]:
        """Persist ``distractor-summary.json`` (public) and return its content."""
        summary = sanitize_public(self.scheduler.summary() if self.scheduler else {})
        (self.run_dir / "distractor-summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        return summary

    def _write_invariant_summary(self) -> dict[str, Any]:
        """Persist ``invariant-summary.json`` (public) and return its content."""
        summary = sanitize_public(self.controller.invariant_summary())
        (self.run_dir / "invariant-summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        return summary

    def request_finish(self) -> asyncio.Task[dict[str, Any]]:
        """Start ``finish()`` in the background (for the agent-facing tool)."""
        if self._finish_task is None:
            self._finish_task = asyncio.create_task(self.finish(), name=f"finish:{self.config.run_id}")
        return self._finish_task

    async def _observe_once(self, *, label: str) -> None:
        async with self._observe_lock:
            result = await self.hooks.observe_snapshot()
        if not isinstance(result, Mapping):
            return
        snapshot = result.get("snapshot")
        if not isinstance(snapshot, Mapping):
            snapshot = result
        await self.controller.observe_snapshot(
            snapshot, snapshot_id=str(result.get("snapshot_id", label))
        )

    async def _observe_after_mutation(self, event: ApiEvent) -> None:
        """Snapshot immediately after a successful mutating main-actor call.

        Runs while the proxy still holds that call's response, so any snapshot
        predicate the new state satisfies fires now — and with
        ``release="after_completed"`` the distractor's write has landed before
        the agent learns its own call succeeded. Without this, snapshot-only
        distractors landed at an arbitrary point of the poll interval, often
        after the agent had verified and finished.
        """
        if self._finished:
            return
        await self._observe_once(label=f"after-{event.service}.{event.operation}-{event.sequence}")

    async def abort(self) -> None:
        if not self._started or self._finished:
            return
        self._finished = True
        cleanup: Mapping[str, Any] | None = None
        cleanup_errors: list[str] = []
        try:
            await self._stop_snapshot_observer()
            cleanup, cleanup_errors = await self._run_cleanup(include_reset=True)
        finally:
            if self.store is not None:
                self.store.close()
            self._write_run_metadata(
                "aborted", {"cleanup": cleanup, "cleanup_errors": cleanup_errors}
            )

    async def _snapshot_loop(self) -> None:
        """Poll the configured cloud observer and feed normalized snapshots."""
        while not self._finished:
            try:
                # Serialize with post-mutation observations: an unserialized
                # poll can start just before a held mutating call lands, read
                # the post-write state, and fire a snapshot trigger *outside*
                # the hold (seen as the ia-minimum-60d post-verification race).
                async with self._observe_lock:
                    result = await self.hooks.observe_snapshot()
                if isinstance(result, Mapping):
                    snapshot = result.get("snapshot")
                    if not isinstance(snapshot, Mapping):
                        snapshot = result
                    self._snapshot_counter += 1
                    snapshot_id = str(
                        result.get("snapshot_id", f"poll-{self._snapshot_counter}")
                    )
                    await self.controller.observe_snapshot(
                        snapshot,
                        snapshot_id=snapshot_id,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.controller.invalid_reason = f"snapshot observer failed: {exc}"
                try:
                    await self.controller.record_runtime(
                        "snapshot.observer_failed", {"error": str(exc)}
                    )
                except Exception:
                    pass
                return
            await asyncio.sleep(self.config.snapshot_poll_interval)

    async def _stop_snapshot_observer(self) -> None:
        task = self._snapshot_task
        self._snapshot_task = None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _run_cleanup(
        self, *, include_reset: bool
    ) -> tuple[dict[str, Any], list[str]]:
        results: dict[str, Any] = {}
        errors: list[str] = []
        stages = []
        if include_reset:
            stages.append(("reset", self.hooks.reset))
        stages.extend(
            (("destroy", self.hooks.destroy), ("leak_check", self.hooks.leak_check))
        )
        for name, hook in stages:
            try:
                results[name] = await hook()
            except Exception as exc:
                results[name] = None
                errors.append(f"{name} failed: {exc}")
        return results, errors

    def _ensure_running(self) -> None:
        if not self._started or self._finished:
            raise RuntimeError("runtime is not accepting submissions")

    def _write_run_metadata(self, status: str, extra: Mapping[str, Any] | None = None) -> None:
        data = {
            "schema_version": 1,
            "run_id": self.config.run_id,
            "status": status,
            "region": self.config.region,
            "runtime_versions": {
                "python": sys.version.split()[0],
                "boto3": version("boto3"),
                "botocore": version("botocore"),
                "mcp": version("mcp"),
                "canonicalizer": CANONICALIZER_VERSION,
            },
            "main_role_arn": self.config.main_role_arn,
            "distractor_role_arns": {
                key: value.role_arn for key, value in self.config.distractors.items()
            },
            "distractor_source_hashes": dict(
                sorted(self._distractor_source_hashes.items())
            ),
            "input_hashes": dict(sorted(self.config.input_hashes.items())),
            "identity_isolation_configured": bool(self.config.main_role_arn)
            and all(value.role_arn for value in self.config.distractors.values()),
            "allow_unscoped_credentials": self.config.allow_unscoped_credentials,
            "certification_eligible": False,
            "security_model": "trusted-prototype",
            "warning": (
                "Cloud state is observed through lifecycle snapshots; agent API submissions are disabled."
            ),
        }
        if extra:
            data.update(sanitize_public(extra))
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "run.json").write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n"
        )
