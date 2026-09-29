"""Versioned records written to the runtime's append-only event timeline."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Iterator, Mapping

SCHEMA_VERSION = 1
CANONICALIZER_VERSION = "aws-runtime-v1"
_SENSITIVE_KEYS = {
    "accesskeyid",
    "authorization",
    "password",
    "secretaccesskey",
    "sessiontoken",
    "token",
    "userdata",
    "x-amz-security-token",
}
_NORMALIZED_SENSITIVE_KEYS = frozenset(
    item.lower().replace("_", "").replace("-", "") for item in _SENSITIVE_KEYS
)



def json_safe(value: Any) -> Any:
    """Convert Botocore values to deterministic JSON-compatible values."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return str(value)
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"$base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Mapping):
        return {str(k): json_safe(v) for k, v in sorted(value.items(), key=lambda x: str(x[0]))}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted((json_safe(item) for item in value), key=repr)
    if dataclasses.is_dataclass(value):
        return json_safe(dataclasses.asdict(value))
    return repr(value)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sanitize_public(value: Any) -> Any:
    """Redact common AWS secret-bearing fields while retaining stable evidence."""
    safe = json_safe(value)
    if isinstance(safe, dict):
        result = {}
        for key, child in safe.items():
            if key.lower().replace("_", "").replace("-", "") in _NORMALIZED_SENSITIVE_KEYS:
                result[key] = {"$redacted_sha256": canonical_digest(child)}
            else:
                result[key] = sanitize_public(child)
        return result
    if isinstance(safe, list):
        return [sanitize_public(child) for child in safe]
    return safe


@dataclass(frozen=True)
class Snapshot(Mapping[str, Any]):
    """Typed envelope for an observed cloud-state snapshot.

    The envelope keeps stable metadata explicit while leaving provider- and
    case-specific fields in ``data``. It implements ``Mapping`` so existing
    JSON-pointer predicates and ``snapshot.get(...)`` lambdas remain natural.
    """

    data: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_value(cls, value: Mapping[str, Any] | "Snapshot") -> "Snapshot":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("snapshot must be a mapping")
        return cls(sanitize_public(value))

    @property
    def resources(self) -> Mapping[str, Any]:
        value = self.data.get("resources", {})
        return value if isinstance(value, Mapping) else {}

    @property
    def captured_at(self) -> str | None:
        value = self.data.get("captured_at", self.data.get("timestamp"))
        return value if isinstance(value, str) else None

    @property
    def provider(self) -> str | None:
        value = self.data.get("provider")
        return value if isinstance(value, str) else None

    @property
    def metadata(self) -> Mapping[str, Any]:
        value = self.data.get("metadata", {})
        return value if isinstance(value, Mapping) else {}

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


@dataclass(frozen=True)
class SnapshotObservation:
    """One normalized cloud-state observation eligible for trigger matching."""

    run_id: str
    sequence: int
    observation_id: str
    snapshot_id: str
    snapshot: Snapshot
    initial: bool = False
    schema_version: int = SCHEMA_VERSION
    kind: str = "snapshot.observed"

    @classmethod
    def create(
        cls,
        run_id: str,
        sequence: int,
        snapshot: Mapping[str, Any] | Snapshot,
        *,
        snapshot_id: str,
        initial: bool = False,
    ) -> "SnapshotObservation":
        return cls(
            run_id=run_id,
            sequence=sequence,
            observation_id=f"{run_id}:{sequence}",
            snapshot_id=snapshot_id,
            snapshot=Snapshot.from_value(snapshot),
            initial=initial,
        )

    @property
    def event_id(self) -> str:
        """Stable trigger-file identity shared with worker diagnostics."""
        return self.observation_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "observation_id": self.observation_id,
            "snapshot_id": self.snapshot_id,
            "snapshot": self.snapshot.to_dict(),
            "initial": self.initial,
            "schema_version": self.schema_version,
            "kind": self.kind,
        }


def runtime_record(run_id: str, sequence: int, kind: str, data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "run_id": run_id,
        "sequence": sequence,
        "event_id": f"{run_id}:{sequence}",
        "wall_time": datetime.now(timezone.utc).isoformat(),
        "monotonic_ns": time.monotonic_ns(),
        "data": sanitize_public(data),
    }


class ActorKind(str, Enum):
    MAIN = "main"
    DISTRACTOR = "distractor"


class ApiPhase(str, Enum):
    BEFORE = "before"
    AFTER_SUCCESS = "after_success"
    AFTER_ERROR = "after_error"


# Operation-name prefixes that never change cloud state (CloudTrail's readOnly
# convention). Anything else is treated as a mutation.
READ_ONLY_OPERATION_PREFIXES = (
    "Get", "List", "Describe", "Head", "Select", "Search", "Query", "Scan", "Lookup",
    "Check", "Test", "Validate", "Preview", "Estimate", "Simulate", "Verify", "Discover",
    "Retrieve", "Count", "Decode", "Assume", "Export", "Batch", "Generate", "Is", "Can",
)


def is_read_only_operation(operation: str) -> bool:
    return operation.startswith(READ_ONLY_OPERATION_PREFIXES)


@dataclass(frozen=True)
class ApiEvent:
    """One phase of one intercepted API call (``kind="api.lifecycle"``)."""

    run_id: str
    sequence: int
    actor_id: str
    actor_kind: ActorKind
    call_id: str
    phase: ApiPhase
    service: str
    operation: str
    region: str
    protocol: str = ""
    api_version: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    parameters_decoded: bool = False
    http: Mapping[str, Any] = field(default_factory=dict)
    outcome: Mapping[str, Any] | None = None
    error: Mapping[str, Any] | None = None
    raw_evidence_digest: str | None = None
    wall_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    monotonic_ns: int = field(default_factory=time.monotonic_ns)
    schema_version: int = SCHEMA_VERSION
    kind: str = "api.lifecycle"
    canonicalizer_version: str = CANONICALIZER_VERSION

    @property
    def event_id(self) -> str:
        return f"{self.run_id}:{self.sequence}"

    @property
    def mutating(self) -> bool:
        return not is_read_only_operation(self.operation)

    @property
    def observation_id(self) -> str:
        """Trigger-file identity, shared with snapshot observations."""
        return self.event_id

    @property
    def snapshot_id(self) -> str:
        return f"api:{self.call_id}:{self.phase.value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "wall_time": self.wall_time,
            "monotonic_ns": self.monotonic_ns,
            "actor_id": self.actor_id,
            "actor_kind": self.actor_kind.value,
            "call_id": self.call_id,
            "phase": self.phase.value,
            "service": self.service,
            "operation": self.operation,
            "region": self.region,
            "protocol": self.protocol,
            "api_version": self.api_version,
            "parameters": sanitize_public(self.parameters),
            "parameters_decoded": self.parameters_decoded,
            "http": sanitize_public(self.http),
            "outcome": sanitize_public(self.outcome) if self.outcome is not None else None,
            "error": sanitize_public(self.error) if self.error is not None else None,
            "raw_evidence_digest": self.raw_evidence_digest,
            "canonicalizer_version": self.canonicalizer_version,
        }

