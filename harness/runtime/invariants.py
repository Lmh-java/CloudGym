"""Safety invariants: snapshot predicates that must hold for the whole run.

A distractor trigger asks "did the state reach X?" once and launches a
program. An invariant asks "does the state still satisfy P?" on every
observation and only keeps a record. That record is what lets an oracle
detect safety interference: an
interleaving that breaks quorum, removes every recovery path, or drops a
guard between the agent's check and its hazardous action may leave a final
snapshot that looks perfectly healthy.

Semantics, per invariant:

* the predicate returns True while the invariant holds;
* the first observation on which it returns False opens a *violation*
  (``invariant.violated``); the next observation on which it holds again
  closes it (``invariant.restored``); a violation still open at finish is
  reported as unrestored;
* a predicate that raises is a monitor failure (``invariant.check_failed``)
  and invalidates the run, in line with trigger predicate failures;
* with ``check_initial`` (the default) the invariant is also evaluated on the
  initial ``S0`` observation and must hold there — a case whose invariant is
  already broken before the agent acts is ill-formed and the run is invalid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .decorators import InvariantMetadata, SnapshotPredicateFn


class InvariantError(RuntimeError):
    pass


@dataclass(frozen=True)
class InvariantDefinition:
    """Where a frozen invariant module lives and what it must hash to."""

    invariant_id: str
    source_path: Path
    sha256: str | None = None


@dataclass(frozen=True)
class InvariantSpec:
    """A loaded invariant ready for evaluation."""

    invariant_id: str
    predicate: SnapshotPredicateFn
    check_initial: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.invariant_id:
            raise ValueError("invariant_id must be non-empty")
        if not callable(self.predicate):
            raise TypeError("predicate must be callable")

    @classmethod
    def from_metadata(cls, invariant_id: str, metadata: InvariantMetadata) -> "InvariantSpec":
        return cls(
            invariant_id=invariant_id,
            predicate=metadata.predicate,
            check_initial=metadata.check_initial,
            metadata={"name": metadata.name, "description": metadata.description,
                      "check_initial": metadata.check_initial},
        )

    def holds(self, snapshot: Mapping[str, Any]) -> bool:
        try:
            return bool(self.predicate(snapshot))
        except Exception as exc:
            raise InvariantError(f"invariant {self.invariant_id} predicate failed: {exc}") from exc


@dataclass
class Violation:
    invariant_id: str
    observation_id: str
    snapshot_id: str
    sequence: int
    initial: bool = False
    restored_observation_id: str | None = None
    restored_snapshot_id: str | None = None
    restored_sequence: int | None = None

    @property
    def restored(self) -> bool:
        return self.restored_observation_id is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "observation_id": self.observation_id,
            "snapshot_id": self.snapshot_id,
            "sequence": self.sequence,
            "initial": self.initial,
            "restored": self.restored,
            "restored_observation_id": self.restored_observation_id,
            "restored_snapshot_id": self.restored_snapshot_id,
            "restored_sequence": self.restored_sequence,
        }


@dataclass(frozen=True)
class InvariantEvent:
    """One transition the controller should persist as a runtime record."""

    kind: str  # invariant.violated | invariant.restored | invariant.check_failed
    invariant_id: str
    data: Mapping[str, Any]


class InvariantMonitor:
    """Tracks the hold/violate state of every invariant across observations.

    Not thread-safe; the controller drives it under its own lock.
    """

    def __init__(self, invariants: tuple[InvariantSpec, ...] = ()):
        ids = [spec.invariant_id for spec in invariants]
        if len(ids) != len(set(ids)):
            raise ValueError("invariant_id values must be unique")
        self.invariants = tuple(invariants)
        self._open: dict[str, Violation] = {}
        self._history: dict[str, list[Violation]] = {spec.invariant_id: [] for spec in invariants}
        self._checks: dict[str, int] = {spec.invariant_id: 0 for spec in invariants}
        self._failed: dict[str, str] = {}

    def observe(self, snapshot: Mapping[str, Any], *, observation_id: str, snapshot_id: str,
                sequence: int, initial: bool = False) -> list[InvariantEvent]:
        """Evaluate every invariant on one observation and return the transitions."""
        events: list[InvariantEvent] = []
        for spec in self.invariants:
            if initial and not spec.check_initial:
                continue
            if spec.invariant_id in self._failed:
                continue
            self._checks[spec.invariant_id] += 1
            try:
                holds = spec.holds(snapshot)
            except InvariantError as exc:
                self._failed[spec.invariant_id] = str(exc)
                events.append(InvariantEvent("invariant.check_failed", spec.invariant_id, {
                    "invariant_id": spec.invariant_id, "observation_id": observation_id,
                    "snapshot_id": snapshot_id, "error": str(exc),
                }))
                continue
            open_violation = self._open.get(spec.invariant_id)
            if not holds and open_violation is None:
                violation = Violation(spec.invariant_id, observation_id, snapshot_id, sequence, initial)
                self._open[spec.invariant_id] = violation
                self._history[spec.invariant_id].append(violation)
                events.append(InvariantEvent("invariant.violated", spec.invariant_id, {
                    "invariant_id": spec.invariant_id, "observation_id": observation_id,
                    "snapshot_id": snapshot_id, "initial": initial,
                    "name": spec.metadata.get("name"),
                }))
            elif holds and open_violation is not None:
                open_violation.restored_observation_id = observation_id
                open_violation.restored_snapshot_id = snapshot_id
                open_violation.restored_sequence = sequence
                del self._open[spec.invariant_id]
                events.append(InvariantEvent("invariant.restored", spec.invariant_id, {
                    "invariant_id": spec.invariant_id, "observation_id": observation_id,
                    "snapshot_id": snapshot_id,
                    "violated_observation_id": open_violation.observation_id,
                }))
        return events

    @property
    def invalid_reason(self) -> str | None:
        """Why the run is not scorable: the monitor broke, or S0 was already bad."""
        if self._failed:
            first = sorted(self._failed)[0]
            return self._failed[first]
        initial = sorted(
            v.invariant_id for history in self._history.values() for v in history if v.initial
        )
        if initial:
            return f"invariants violated in the initial state: {initial}"
        return None

    def summary(self) -> dict[str, Any]:
        """Public, JSON-safe record; also the oracle's ``input.invariants``."""
        per_invariant = {}
        for spec in self.invariants:
            history = self._history[spec.invariant_id]
            per_invariant[spec.invariant_id] = {
                **spec.metadata,
                "checks": self._checks[spec.invariant_id],
                "violations": [v.to_dict() for v in history],
                "violation_count": len(history),
                "holds_at_end": spec.invariant_id not in self._open,
                "check_error": self._failed.get(spec.invariant_id),
            }
        violated = sorted(i for i, h in self._history.items() if h)
        return {
            "invariants": per_invariant,
            "violated": violated,
            "unrestored": sorted(self._open),
            "check_failed": sorted(self._failed),
            "invalid_reason": self.invalid_reason,
        }
