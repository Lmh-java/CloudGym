"""Write-through orchestration state for one batch: ``<batch>/ledger.json``.

    pending -> running -> done | failed          (terminal)
                       | interrupted -> pending  (rerun from scratch)
    done | failed -> contaminated                (terminal; ``bench audit --mark``)
    contaminated -> pending                      (``bench requeue --contaminated``)
    failed | contaminated -> pending             (``bench watch`` auto-rerun, up to N finished attempts)

A *contaminated* cell is one whose agent read outside its workspace (case material,
harness files, other cells: ``harness.bench.audit``). It keeps its attempts and run
directory, is excluded from every table, and is rerun only when released.

The ledger records orchestration only; every metric lives in the cell's own
run directory. Opening a ledger never resets it: new cells are added as
pending, cells the spec dropped are kept (``orphaned``), and a changed
``spec_hash`` is logged as drift, not treated as a new batch.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .spec import Cell

TERMINAL = {"done", "failed", "contaminated"}
# Attempt outcomes that count against the auto-rerun budget: the cell actually ran to an end.
# Interruptions (rate limits, operator stops, network) never do.
FINISHED_OUTCOMES = {"done", "failed"}


class LedgerError(RuntimeError):
    pass


def _atomic_write(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def append_event(batch_dir: Path, event: str, **fields: Any) -> None:
    batch_dir.mkdir(parents=True, exist_ok=True)
    with open(batch_dir / "events.jsonl", "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, sort_keys=True) + "\n")


def rename_partial(run_dir: Path, tag: str = "int") -> Path | None:
    """Move a superseded run dir aside as ``<name>.<tag><N>``; None if absent."""
    if not run_dir.exists():
        return None
    n = 1
    while True:
        candidate = run_dir.with_name(f"{run_dir.name}.{tag}{n}")
        if not candidate.exists():
            os.replace(run_dir, candidate)
            return candidate
        n += 1


@dataclass
class Ledger:
    batch_dir: Path
    data: dict[str, Any]

    @property
    def path(self) -> Path:
        return self.batch_dir / "ledger.json"

    @classmethod
    def open(cls, batch_dir: Path, *, batch: str, spec_hash: str, cells: Iterable[Cell]) -> "Ledger":
        batch_dir = Path(batch_dir)
        path = batch_dir / "ledger.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                raise LedgerError(f"corrupt ledger {path}: {exc}; refusing to restart finished work") from None
            if data.get("batch") != batch:
                raise LedgerError(f"{path} belongs to batch {data.get('batch')!r}, not {batch!r}")
            if data.get("spec_hash") != spec_hash:
                append_event(batch_dir, "spec-drift", previous=data.get("spec_hash"), current=spec_hash)
                data["spec_hash"] = spec_hash
        else:
            data = {"schema_version": 1, "batch": batch, "spec_hash": spec_hash,
                    "created_at": round(time.time(), 3), "cells": {}}
        known = set()
        for cell in cells:
            known.add(cell.key)
            entry = data["cells"].setdefault(cell.key, {"status": "pending", "run_id": cell.run_id, "attempts": []})
            entry.pop("orphaned", None)
            entry["run_id"] = cell.run_id
            if cell.arm.hold:
                entry["held"] = True
            else:
                entry.pop("held", None)
        for key, entry in data["cells"].items():
            if key not in known:
                entry["orphaned"] = True
        ledger = cls(batch_dir, data)
        ledger.save()
        return ledger

    def save(self) -> None:
        self.batch_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.path, self.data)

    # -- queries --------------------------------------------------------------

    def entry(self, key: str) -> dict[str, Any]:
        return self.data["cells"][key]

    def status(self, key: str) -> str:
        return self.entry(key)["status"]

    def pending(self, cells: Iterable[Cell]) -> list[Cell]:
        """Cells the next run executes: pending/interrupted and not held (``arm.hold``)."""
        return [c for c in cells if self.status(c.key) in {"pending", "interrupted"} and not self.entry(c.key).get("held")]

    def requeue(self, key: str, *, reason: str | None = None) -> None:
        """Put a failed/interrupted cell back to ``pending`` (attempts are kept)."""
        entry = self.entry(key)
        if entry["status"] in ("pending", "running"):
            return
        entry["status"] = "pending"
        entry["updated_at"] = round(time.time(), 3)
        self.save()
        append_event(self.batch_dir, "cell-requeued", cell=key, reason=reason)

    def mark_contaminated(self, key: str, *, reason: str) -> bool:
        """Retire a finished cell whose agent read outside its workspace; False if not finished."""
        entry = self.entry(key)
        if entry["status"] not in ("done", "failed"):
            return False
        entry["status"] = "contaminated"
        entry["contaminated"] = {"reason": reason, "at": round(time.time(), 3)}
        entry["updated_at"] = round(time.time(), 3)
        self.save()
        append_event(self.batch_dir, "cell-contaminated", cell=key, reason=reason)
        return True

    def auto_requeue(self, cells: Iterable[Cell], *, max_attempts: int) -> tuple[list[tuple[str, str]], list[str]]:
        """Put ``failed`` (a harness fault: a model's wrong answer is ``done``) and ``contaminated``
        cells back to pending while they have fewer than ``max_attempts`` finished attempts.

        Returns ``(requeued, exhausted)``: ``(key, why)`` per requeued cell, and the keys that hit
        the budget in this call (each is reported once; ``auto_rerun_exhausted`` marks it)."""
        requeued: list[tuple[str, str]] = []
        exhausted: list[str] = []
        for cell in cells:
            entry = self.data["cells"].get(cell.key)
            if not entry or entry.get("orphaned") or entry["status"] not in ("failed", "contaminated"):
                continue
            finished = sum(1 for a in entry.get("attempts", []) if a.get("outcome") in FINISHED_OUTCOMES)
            last = entry["attempts"][-1] if entry.get("attempts") else {}
            cause = (str((entry.get("contaminated") or {}).get("reason") or "contaminated")
                     if entry["status"] == "contaminated" else str(last.get("reason") or "failed"))
            if finished >= max_attempts:
                if not entry.get("auto_rerun_exhausted"):
                    entry["auto_rerun_exhausted"] = True
                    self.save()
                    append_event(self.batch_dir, "cell-auto-rerun-exhausted", cell=cell.key, attempts=finished)
                    exhausted.append(cell.key)
                continue
            why = f"auto-rerun {finished + 1}/{max_attempts}: {entry['status']} ({cause[:120]})"
            self.requeue(cell.key, reason=why)
            requeued.append((cell.key, why))
        return requeued, exhausted

    def clear_contamination(self, key: str, *, run_dir_name: str, reason: str) -> bool:
        """Undo a contamination mark the audit no longer supports: the cell goes back to its last
        finished attempt's outcome. Also covers a cell auto-rerun already requeued but has not
        started again (its last attempt, in ``run_dir_name``, is still the audited one)."""
        entry = self.entry(key)
        last = entry["attempts"][-1] if entry.get("attempts") else {}
        if not entry.get("contaminated") or entry["status"] not in ("contaminated", "pending"):
            return False
        if last.get("outcome") not in ("done", "failed") or Path(str(last.get("run_dir"))).name != run_dir_name:
            return False
        entry["status"] = last["outcome"]
        entry["cleared_contamination"] = {**entry.pop("contaminated"), "cleared": reason, "at": round(time.time(), 3)}
        entry.pop("auto_rerun_exhausted", None)
        entry["updated_at"] = round(time.time(), 3)
        self.save()
        append_event(self.batch_dir, "cell-contamination-cleared", cell=key, reason=reason)
        return True

    def held(self, cells: Iterable[Cell]) -> list[Cell]:
        return [c for c in cells if self.entry(c.key).get("held") and self.status(c.key) not in TERMINAL]

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for key, entry in self.data["cells"].items():
            if entry.get("orphaned"):
                continue
            status = entry["status"] + (" (held)" if entry.get("held") and entry["status"] not in TERMINAL else "")
            counts[status] = counts.get(status, 0) + 1
        return counts

    # -- transitions ----------------------------------------------------------

    def start(self, cell: Cell, run_dir: Path, *, account: str | None = None, route: str | None = None) -> int:
        entry = self.entry(cell.key)
        if entry["status"] in TERMINAL:
            raise LedgerError(f"{cell.key} is already {entry['status']}")
        n = len(entry["attempts"]) + 1
        entry["attempts"].append({"n": n, "started_at": round(time.time(), 3), "ended_at": None,
                                  "outcome": None, "reason": None, "run_dir": str(run_dir),
                                  **({"account": account} if account else {}), **({"route": route} if route else {})})
        entry["status"] = "running"
        entry["updated_at"] = round(time.time(), 3)
        self.save()
        append_event(self.batch_dir, "cell-start", cell=cell.key, attempt=n, account=account,
                     **({"route": route} if route else {}))
        return n

    def finish(self, cell: Cell, outcome: str, reason: str | None = None, **fields: Any) -> None:
        if outcome not in {"done", "failed", "interrupted", "contaminated"}:
            raise ValueError(f"unknown outcome {outcome!r}")
        entry = self.entry(cell.key)
        if entry["attempts"]:
            attempt = entry["attempts"][-1]
            attempt.update(ended_at=round(time.time(), 3), outcome=outcome, reason=reason, **fields)
        entry["status"] = outcome
        entry["updated_at"] = round(time.time(), 3)
        self.save()
        append_event(self.batch_dir, f"cell-{outcome}", cell=cell.key, reason=reason, **fields)

    def reconcile_running(self, cells: Iterable[Cell]) -> list[str]:
        """Cells left 'running' by a crashed process become 'interrupted'."""
        fixed = []
        for cell in cells:
            entry = self.entry(cell.key)
            if entry["status"] == "running":
                entry["status"] = "interrupted"
                if entry["attempts"] and entry["attempts"][-1]["outcome"] is None:
                    entry["attempts"][-1].update(outcome="interrupted", reason="process died",
                                                 ended_at=round(time.time(), 3))
                fixed.append(cell.key)
        if fixed:
            self.save()
            for key in fixed:
                append_event(self.batch_dir, "cell-reconciled", cell=key)
        return fixed
