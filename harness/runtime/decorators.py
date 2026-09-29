"""Decorators embedded in generated Step 3 distractor and invariant modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

SnapshotPredicateFn = Callable[[Mapping[str, Any]], bool]


@dataclass(frozen=True)
class ApiTriggerSpec:
    """Fire when the main actor issues ``service.operation`` (see ``on_api``)."""

    service: str
    operation: str
    phase: str = "before"
    where: Callable[[Mapping[str, Any]], bool] | None = None
    occurrence: int = 1


def on_api(service: str, operation: str, *, phase: str = "before",
           where: Callable[[Mapping[str, Any]], bool] | None = None,
           occurrence: int = 1) -> ApiTriggerSpec:
    """Declare an API trigger: ``where`` receives the decoded request parameters.

    ``occurrence`` fires on the Nth matching call (e.g. 2 = the agent's second
    write of that operation) — the deterministic way to interfere with a
    correction rather than the initial write.
    """
    if where is not None and not callable(where):
        raise TypeError("where must be callable")
    if occurrence < 1:
        raise ValueError("occurrence must be >= 1")
    return ApiTriggerSpec(service=service, operation=operation, phase=phase, where=where,
                          occurrence=occurrence)


@dataclass(frozen=True)
class DistractorMetadata:
    role: str
    responsibility: str
    intent: str
    predicate: SnapshotPredicateFn | None
    fire_once: bool = True
    # Refusal cycles (execution conflict, dial one): the trigger that fired first re-fires on
    # each later match, up to this many launches in all; None keeps fire_once's meaning.
    max_fires: int | None = None
    api: ApiTriggerSpec | None = None
    release: str = "after_started"
    # What this principal answers when consulted about the state it touched: the
    # reconciliation this case expects, in the policy's own register (a convention, never a
    # field or a value the utterance did not give). Read only at `consult` awareness, and
    # only for a distractor that has already landed. ``subject`` is what the agent must name
    # to reach it.
    resolution: str = ""
    subject: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvariantMetadata:
    """A global safety property that must hold in every observed snapshot.

    ``predicate`` returns True while the property holds. Unlike a distractor
    trigger, an invariant never launches anything: the runtime only records
    when it stops holding and when it holds again, so a transient violation
    that the final snapshot hides is still visible to the oracle.
    """

    name: str
    description: str
    predicate: SnapshotPredicateFn
    check_initial: bool = True


def distract(*, role: str, responsibility: str, intent: str,
             predicate: SnapshotPredicateFn | None = None,
             api: ApiTriggerSpec | None = None,
             release: str = "after_started",
             fire_once: bool = True,
             max_fires: int | None = None,
             resolution: str = "",
             subject: tuple[str, ...] | list[str] = ()):
    """Register generated distractor metadata without executing its body.

    ``predicate`` fires on observed snapshots; ``api`` fires on an intercepted
    main-actor API call, which is held until this distractor has started
    (``release="after_started"``) or finished (``"after_completed"``).

    ``resolution`` is what this principal replies when consulted, at the ``consult``
    awareness level where the policy is withheld from the prompt. What reaches it is the
    ``fingerprint`` its ``run()`` returns: the facts that are in the account only because
    the program ran, which the agent must have read and cited. ``subject`` (concept words)
    is optional and only routes at the retired ``consult_open`` control; a subject with no
    resolution answers nothing and is rejected.
    """
    if predicate is not None and not callable(predicate):
        raise TypeError("predicate must be callable")
    if predicate is None and api is None:
        raise TypeError("distract() needs a snapshot predicate, an api trigger, or both")
    if api is not None and not isinstance(api, ApiTriggerSpec):
        raise TypeError("api must come from on_api(...)")
    if api is not None and api.occurrence >= 2 and predicate is None:
        raise ValueError(
            "an occurrence >= 2 api trigger needs a snapshot predicate fallback: "
            "certification requires every distractor to fire, and a route that never "
            "makes the Nth matching call must still be reachable through state")
    if release not in {"after_started", "after_completed"}:
        raise ValueError("release must be after_started or after_completed")
    if max_fires is not None and (not isinstance(max_fires, int) or max_fires < 1):
        raise ValueError("max_fires must be a positive integer")
    subject = tuple(subject)
    if subject and not resolution.strip():
        raise ValueError("a subject with no resolution answers nothing")
    if any(not isinstance(token, str) or not token.strip() for token in subject):
        raise ValueError("every subject must be a non-empty string")

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        metadata = DistractorMetadata(role, responsibility, intent, predicate, fire_once, max_fires, api,
                                      release, resolution.strip(), subject)
        setattr(function, "__cloudgym_distractor__", metadata)
        return function

    return decorate


def invariant(*, name: str, description: str, predicate: SnapshotPredicateFn,
              check_initial: bool = True):
    """Register a safety invariant declaration without executing its body.

    The decorated function is documentation only; the runtime evaluates
    ``predicate`` against every observed snapshot. With ``check_initial`` the
    invariant must already hold in ``S0``; a case whose invariant is violated
    before the agent acts is ill-formed and the run is marked invalid.
    """
    if not callable(predicate):
        raise TypeError("predicate must be callable")
    if not name:
        raise ValueError("name must be non-empty")

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        metadata = InvariantMetadata(name, description, predicate, check_initial)
        setattr(function, "__cloudgym_invariant__", metadata)
        return function

    return decorate


def _single_declaration(module: Any, attribute: str, label: str) -> Any:
    found = [getattr(value, attribute) for value in vars(module).values()
             if hasattr(value, attribute)]
    if len(found) != 1:
        raise ValueError(
            f"{label} module must contain exactly one @{label} declaration; found {len(found)}"
        )
    return found[0]


def load_metadata(module: Any) -> DistractorMetadata:
    """Find the single ``@distract`` declaration in an imported module."""
    return _single_declaration(module, "__cloudgym_distractor__", "distract")


def load_invariant_metadata(module: Any) -> InvariantMetadata:
    """Find the single ``@invariant`` declaration in an imported module."""
    return _single_declaration(module, "__cloudgym_invariant__", "invariant")
