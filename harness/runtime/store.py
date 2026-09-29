"""Single-writer append-only storage for runtime events."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping


class EventStoreError(RuntimeError):
    pass


class JsonlEventStore:
    """Durably append events; a controller must serialize calls to append."""

    def __init__(self, path: Path, *, fsync: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("a", encoding="utf-8")
        self._fsync = fsync

    def append(self, record: Mapping[str, Any]) -> None:
        try:
            self._stream.write(
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                + "\n"
            )
            self._stream.flush()
            if self._fsync:
                os.fsync(self._stream.fileno())
        except (OSError, TypeError, ValueError) as exc:
            raise EventStoreError(f"cannot append event to {self.path}: {exc}") from exc

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> "JsonlEventStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
