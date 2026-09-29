"""Build runtime trigger and distractor definitions from plain JSON data.

Shared by the ``runtime.json`` loader (``app.py``) and the in-process
``run-case`` driver, which assembles the same structures from a case directory.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from typing import Any, Mapping

from .decorators import load_invariant_metadata, load_metadata
from .distractors import DistractorDefinition
from .invariants import InvariantDefinition, InvariantSpec
from .matcher import ApiMatcher, SnapshotMatcher, SnapshotPredicate, TriggerSpec


def _load_module(source_path: Path, module_name: str, label: str):
    spec = importlib.util.spec_from_file_location(module_name, source_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {label} module: {source_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_distractor_module(source_path: Path, distractor_id: str):
    """Import a generated distractor module without executing its body."""
    return _load_module(source_path, f"cloudgym_distractor_{distractor_id}", "distractor")


def load_invariant_module(source_path: Path, invariant_id: str):
    """Import a generated invariant module without executing its body."""
    return _load_module(source_path, f"cloudgym_invariant_{invariant_id}", "invariant")


def declared_invariant(definition: InvariantDefinition) -> InvariantSpec:
    """The invariant an ``invariant.py`` module declares through ``@invariant``."""
    if definition.sha256 and sha256_file(definition.source_path) != definition.sha256:
        raise ValueError(f"invariant {definition.invariant_id} hash mismatch")
    metadata = load_invariant_metadata(
        load_invariant_module(definition.source_path, definition.invariant_id)
    )
    return InvariantSpec.from_metadata(definition.invariant_id, metadata)


def declared_triggers_for(definition: DistractorDefinition) -> tuple[TriggerSpec, ...]:
    """The trigger(s) a distractor module declares through ``@distract``.

    A snapshot predicate yields ``<id>``; an API trigger yields ``<id>:api``.
    """
    metadata = load_metadata(load_distractor_module(definition.source_path, definition.distractor_id))
    common = dict(
        distractor_ids=(definition.distractor_id,),
        required=False,
        release=metadata.release,
        metadata={"role": metadata.role, "responsibility": metadata.responsibility,
                  "intent": metadata.intent, "fire_once": metadata.fire_once, "max_fires": metadata.max_fires,
                  "resolution": metadata.resolution, "subject": list(metadata.subject)},
    )
    triggers: list[TriggerSpec] = []
    if metadata.predicate is not None:
        triggers.append(TriggerSpec(
            trigger_id=definition.distractor_id,
            matcher=SnapshotMatcher(predicates=(metadata.predicate,)), **common))
    if metadata.api is not None:
        triggers.append(TriggerSpec(
            trigger_id=f"{definition.distractor_id}:api",
            matcher=ApiMatcher(service=metadata.api.service, operation=metadata.api.operation,
                               phase=metadata.api.phase, where=metadata.api.where),
            occurrence=getattr(metadata.api, "occurrence", 1), **common))
    return tuple(triggers)


def declared_trigger(definition: DistractorDefinition) -> TriggerSpec:
    """Backward-compatible single-trigger accessor (first declared trigger)."""
    return declared_triggers_for(definition)[0]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def triggers_from_config(items: list[Mapping[str, Any]], declared: list[TriggerSpec] = None) -> tuple[TriggerSpec, ...]:
    result = []
    for item in items:
        matcher = item["matcher"]
        predicates = tuple(
            SnapshotPredicate(**value) for value in matcher.get("predicates", [])
        )
        result.append(
            TriggerSpec(
                trigger_id=item["trigger_id"],
                matcher=SnapshotMatcher(predicates=predicates),
                distractor_ids=tuple(item["distractor_ids"]),
                occurrence=item.get("occurrence", 1),
                required=item.get("required", True),
                release=item.get("release", "after_started"),
                metadata=item.get("metadata", {}),
            )
        )
    return tuple([*result, *(declared or [])])



def invariants_from_config(items: list[Mapping[str, Any] | str], base: Path) -> tuple[InvariantSpec, ...]:
    """Load ``invariants`` entries: a path string or ``{"invariant_id", "source", "sha256"?}``."""
    specs: list[InvariantSpec] = []
    seen: set[str] = set()
    for item in items:
        if isinstance(item, str):
            source_name = Path(item)
            item = {"source": item, "invariant_id":
                    source_name.parent.name if source_name.stem == "invariant" else source_name.stem}
        invariant_id = item["invariant_id"]
        if invariant_id in seen:
            raise ValueError(f"duplicate invariant_id: {invariant_id}")
        seen.add(invariant_id)
        source = Path(item["source"])
        if not source.is_absolute():
            source = base / source
        if not source.is_file():
            raise ValueError(f"missing invariant source: {source}")
        specs.append(declared_invariant(InvariantDefinition(
            invariant_id=invariant_id, source_path=source.resolve(), sha256=item.get("sha256"),
        )))
    return tuple(specs)


def distractors_from_config(items: list[Mapping[str, Any]], base: Path) -> tuple[dict[str, DistractorDefinition], list[TriggerSpec]]:
    result = {}
    declared = []
    seen_ids: set[str] = set()
    for item in items:
        if isinstance(item, str):
            source_name = Path(item)
            item = {"source": item, "distractor_id":
                    source_name.parent.name if source_name.stem == "distractor" else source_name.stem}
        distractor_id = item["distractor_id"]
        if distractor_id in seen_ids:
            raise ValueError(f"duplicate distractor_id: {item['distractor_id']}")
        seen_ids.add(distractor_id)
    for item in items:
        if isinstance(item, str):
            source_name = Path(item)
            item = {"source": item, "distractor_id":
                    source_name.parent.name if source_name.stem == "distractor" else source_name.stem}
        source = Path(item["source"])
        if not source.is_absolute():
            source = base / source
        definition = DistractorDefinition(
            distractor_id=item["distractor_id"],
            source_path=source.resolve(),
            sha256=item.get("sha256"),
            role_arn=item.get("role_arn"),
            environment=item.get("environment", {}),
            timeout=item.get("timeout", 120.0),
        )
        if not definition.source_path.is_file():
            raise ValueError(f"missing distractor source: {definition.source_path}")
        result[definition.distractor_id] = definition
        declared.extend(declared_triggers_for(definition))
    return result, declared
