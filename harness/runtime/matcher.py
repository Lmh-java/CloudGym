"""Typed predicates for observed snapshots and intercepted API calls.

Snapshot triggers fire when the runtime publishes an observed snapshot; API
triggers fire when the proxy publishes the ``before`` phase of a main-actor
call, which is held until the matching distractors have started.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from .events import ApiEvent



class MatchError(RuntimeError):
    pass


_MISSING = object()


def json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise MatchError(f"invalid RFC 6901 JSON pointer: {pointer!r}")
    current = document
    for raw in pointer[1:].split("/"):
        index = 0
        while index < len(raw):
            if raw[index] == "~":
                if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                    raise MatchError(f"invalid RFC 6901 escape in pointer: {pointer!r}")
                index += 2
            else:
                index += 1
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            try:
                if token == "-" or not token.isdigit() or (
                    len(token) > 1 and token.startswith("0")
                ):
                    return _MISSING
                current = current[int(token)]
            except IndexError:
                return _MISSING
        else:
            return _MISSING
    return current


@dataclass(frozen=True)
class SnapshotPredicate:
    """One RFC 6901 predicate over a normalized snapshot document."""

    path: str
    op: str
    value: Any = None

    def matches(self, snapshot: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> bool:
        actual = json_pointer(snapshot, self.path)
        if self.op == "exists":
            return actual is not _MISSING
        if self.op == "changed":
            if previous is None:
                return False
            return actual != json_pointer(previous, self.path)
        if actual is _MISSING:
            return False
        if self.op == "eq":
            return actual == self.value
        if self.op == "contains":
            if isinstance(actual, Mapping) and isinstance(self.value, Mapping):
                return all(actual.get(key, _MISSING) == value
                           for key, value in self.value.items())
            if isinstance(actual, (list, str, Mapping)):
                return self.value in actual
            return False
        raise MatchError(f"unsupported snapshot predicate operator: {self.op!r}")


@dataclass(frozen=True)
class SnapshotMatcher:
    predicates: tuple[SnapshotPredicate | Callable[[Mapping[str, Any]], bool], ...] = ()

    def matches(
        self,
        snapshot: Mapping[str, Any],
        previous: Mapping[str, Any] | None = None,
    ) -> bool:
        for predicate in self.predicates:
            if isinstance(predicate, SnapshotPredicate):
                matched = predicate.matches(snapshot, previous)
            else:
                try:
                    matched = bool(predicate(snapshot))
                except Exception as exc:
                    raise MatchError(f"snapshot predicate failed: {exc}") from exc
            if not matched:
                return False
        return True


@dataclass(frozen=True)
class ParameterPredicate:
    """One RFC 6901 predicate over decoded API parameters."""

    path: str
    op: str
    value: Any = None

    def matches(self, parameters: Mapping[str, Any]) -> bool:
        actual = json_pointer(parameters, self.path)
        if self.op == "exists":
            return actual is not _MISSING
        if actual is _MISSING:
            return False
        if self.op == "eq":
            return actual == self.value
        if self.op == "contains":
            if isinstance(actual, Mapping) and isinstance(self.value, Mapping):
                return all(actual.get(key, _MISSING) == value
                           for key, value in self.value.items())
            if isinstance(actual, (list, str, Mapping)):
                return self.value in actual
            return False
        raise MatchError(f"unsupported parameter predicate operator: {self.op!r}")


@dataclass(frozen=True)
class ApiMatcher:
    """Match one main-actor API call by service, operation, phase and params."""

    service: str
    operation: str
    phase: str = "before"
    predicates: tuple[ParameterPredicate, ...] = ()
    where: Callable[[Mapping[str, Any]], bool] | None = None

    def __post_init__(self) -> None:
        if self.phase not in {"before", "after_success", "after_error"}:
            raise ValueError("phase must be before, after_success or after_error")

    def matches(self, event: "ApiEvent") -> bool:
        if event.service.lower() != self.service.lower():
            return False
        if event.operation.lower() != self.operation.lower():
            return False
        if event.phase.value != self.phase:
            return False
        for predicate in self.predicates:
            if not predicate.matches(event.parameters):
                return False
        if self.where is not None:
            try:
                return bool(self.where(event.parameters))
            except Exception as exc:
                raise MatchError(f"api predicate failed: {exc}") from exc
        return True


@dataclass(frozen=True)
class TriggerSpec:
    trigger_id: str
    matcher: SnapshotMatcher | ApiMatcher
    distractor_ids: tuple[str, ...]
    occurrence: int = 1
    required: bool = True
    release: str = "after_started"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.trigger_id:
            raise ValueError("trigger_id must be non-empty")
        if self.occurrence < 1:
            raise ValueError("occurrence must be >= 1")
        if not self.distractor_ids:
            raise ValueError("trigger requires at least one distractor")
        if self.release not in {"after_started", "after_completed"}:
            raise ValueError("release must be after_started or after_completed")

    @property
    def kind(self) -> str:
        return "api" if isinstance(self.matcher, ApiMatcher) else "snapshot"
