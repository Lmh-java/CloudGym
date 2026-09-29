"""Lease broker over the configured sandbox accounts, tracked in a local file.

    clean -> leased -> clean            (released after a clean leak check)
                    -> dirty            (leak, failed teardown, or the holder died)
    dirty | quarantined -> clean        (only `sandbox-pool reset`)

State lives in ``.cloudgym/pool-state.json`` next to the AWS target config; every
read-modify-write holds ``fcntl.flock`` on ``.cloudgym/pool.lock`` so the bench
daemon, a certifying ``gen-case`` session and ``sandbox-pool`` itself coordinate
through one file. Accounts come from the config (``load_pool_targets``); the state
file only remembers what happened to them, so adding an account to the config is
enough to make it leasable and dropping one forgets its state.

A lease whose holder process is gone is *stale*: the account becomes ``dirty``, never
``clean`` — a run that died mid-deploy strands its seed resources, and the next
tenant would collide with them.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from harness.aws_safety import AwsTarget, config_path, load_pool_targets
from harness.procutil import pid_alive

STATES = ("clean", "leased", "dirty", "quarantined")
STATE_FILE = "pool-state.json"
LOCK_FILE = "pool.lock"


class PoolError(RuntimeError):
    pass


class PoolExhausted(PoolError):
    """No clean account, and the caller chose not to wait."""


@dataclass(frozen=True)
class Lease:
    target: AwsTarget
    label: str
    pid: int
    since: float

    @property
    def account_id(self) -> str:
        return self.target.account_id


def _atomic_write(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


class Pool:
    """``Pool.open(repo_root)`` reads the targets; ``acquire``/``release`` mutate the state file."""

    def __init__(self, targets: Sequence[AwsTarget], state_dir: Path, *, pid: int | None = None):
        if not targets:
            raise PoolError("no sandbox accounts configured")
        self.targets = {t.account_id: t for t in targets}
        self.order = [t.account_id for t in targets]
        self.state_path = state_dir / STATE_FILE
        self.lock_path = state_dir / LOCK_FILE
        self.pid = pid or os.getpid()

    @classmethod
    def open(cls, repo_root: Path, *, limit: int | None = None) -> "Pool":
        """Every configured account (primary first), optionally capped to the first ``limit``."""
        targets = load_pool_targets(repo_root)
        if limit is not None:
            if limit < 1:
                raise PoolError("--slots must be at least 1")
            targets = targets[:limit]
        return cls(targets, config_path(repo_root).parent)

    # -- state file -----------------------------------------------------------

    @contextmanager
    def _locked(self) -> Iterator[dict[str, dict[str, Any]]]:
        """Yield the per-account state under the exclusive lock; changes are written on exit."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                state = self._read()
                yield state
                _atomic_write(self.state_path, {"schema_version": 1, "accounts": state})
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.state_path.read_text())
            accounts = data.get("accounts", {}) if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            accounts = {}
        # Every account in the file is kept (a pool opened with ``limit`` sees only its own
        # ``order`` but must never drop the other accounts' leases when it writes the file
        # back: doing so erased running batches' leases on 2026-09-22); new ones start clean.
        state = {}
        for account_id, entry in accounts.items():
            if not isinstance(entry, dict):
                entry = {"state": "dirty", "last_error": f"unreadable entry {entry!r}"}
            if entry.get("state") not in STATES:
                entry["state"] = "dirty"
                entry["last_error"] = f"unknown state {entry.get('state')!r}"
            state[account_id] = entry
        for account_id in self.order:
            state.setdefault(account_id, {"state": "clean"})
        return state

    def _reap_stale(self, state: dict[str, dict[str, Any]]) -> list[str]:
        reaped = []
        for account_id, entry in state.items():
            holder = entry.get("holder") or {}
            if entry.get("state") == "leased" and holder.get("pid") and not pid_alive(int(holder["pid"])):
                entry.update(state="dirty", holder=None, since=time.time(),
                             last_error=f"holder pid {holder['pid']} ({holder.get('label')}) died while leased")
                reaped.append(account_id)
        return reaped

    # -- leases -----------------------------------------------------------------

    def try_acquire(self, label: str, *, run_id: str | None = None) -> Lease | None:
        """Lease the first clean account, or None when none is clean right now."""
        with self._locked() as state:
            self._reap_stale(state)
            for account_id in self.order:
                entry = state[account_id]
                if entry.get("state") != "clean":
                    continue
                now = time.time()
                entry.update(state="leased", since=now,
                             holder={"pid": self.pid, "label": label, "run_id": run_id})
                entry.pop("last_error", None)
                return Lease(self.targets[account_id], label, self.pid, now)
        return None

    def acquire(self, label: str, *, run_id: str | None = None, wait: bool = True,
                timeout: float | None = None, poll: float = 2.0) -> Lease:
        """Lease a clean account, blocking (polling the file) until one frees up.

        Raises ``PoolExhausted`` when ``wait`` is False, when ``timeout`` elapses, or
        when every account is dirty/quarantined so waiting could never succeed."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            lease = self.try_acquire(label, run_id=run_id)
            if lease is not None:
                return lease
            counts = self.counts()
            if not counts.get("leased"):
                raise PoolExhausted(f"no clean sandbox account: {self._summary(counts)}; "
                                    "run `sandbox-pool reset <account>` after sweeping it")
            if not wait or (deadline is not None and time.monotonic() >= deadline):
                raise PoolExhausted(f"no clean sandbox account free: {self._summary(counts)}")
            time.sleep(poll)

    async def acquire_async(self, label: str, *, run_id: str | None = None,
                            timeout: float | None = None, poll: float = 2.0, abort=None) -> Lease | None:
        """``acquire`` without blocking the event loop between polls. ``abort`` (a callable) is
        checked between polls: when it returns true the wait ends with None, nothing leased
        (a drain or a yield arrived while every account was busy)."""
        import asyncio
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if abort is not None and abort():
                return None
            lease = await asyncio.to_thread(self.try_acquire, label, run_id=run_id)
            if lease is not None:
                return lease
            counts = self.counts()
            if not counts.get("leased"):
                raise PoolExhausted(f"no clean sandbox account: {self._summary(counts)}; "
                                    "run `sandbox-pool reset <account>` after sweeping it")
            if deadline is not None and time.monotonic() >= deadline:
                raise PoolExhausted(f"no clean sandbox account free: {self._summary(counts)}")
            await asyncio.sleep(poll)

    def release(self, lease: Lease, *, clean: bool, error: str | None = None) -> str:
        """Return the account: ``clean`` back to the pool, otherwise ``dirty``. Returns the new state."""
        with self._locked() as state:
            entry = state.get(lease.account_id)
            if entry is None:
                raise PoolError(f"account {lease.account_id} is not in the pool")
            holder = entry.get("holder") or {}
            if entry.get("state") != "leased" or holder.get("pid") != lease.pid:
                raise PoolError(f"account {lease.account_id} is not leased by pid {lease.pid} "
                                f"(state={entry.get('state')}, holder={holder})")
            new_state = "clean" if clean else "dirty"
            entry.update(state=new_state, holder=None, since=time.time(),
                         last_run={"label": lease.label, "elapsed_s": round(time.time() - lease.since, 1)})
            if error:
                entry["last_error"] = error[:500]
            else:
                entry.pop("last_error", None)
            return new_state

    def mark(self, account_id: str, new_state: str, *, reason: str | None = None) -> None:
        """Operator transition (``sandbox-pool reset`` / quarantine); refuses to override a live lease."""
        if new_state not in STATES or new_state == "leased":
            raise PoolError(f"cannot mark an account {new_state!r}")
        with self._locked() as state:
            entry = state.get(account_id)
            if entry is None:
                raise PoolError(f"account {account_id} is not in the pool")
            self._reap_stale(state)
            if entry.get("state") == "leased":
                raise PoolError(f"account {account_id} is leased by {entry.get('holder')}; stop that run first")
            entry.update(state=new_state, holder=None, since=time.time())
            if reason:
                entry["last_error"] = reason[:500]
            else:
                entry.pop("last_error", None)

    # -- queries ----------------------------------------------------------------

    def status(self) -> list[dict[str, Any]]:
        """One row per account, in pool order, after reaping stale leases."""
        with self._locked() as state:
            self._reap_stale(state)
            rows = []
            for account_id in self.order:
                target = self.targets[account_id]
                entry = state[account_id]
                rows.append({"account_id": account_id, "label": target.label, "profile": target.profile,
                             "access": target.access, **{k: entry.get(k) for k in
                                                          ("state", "since", "holder", "last_error", "last_run")}})
            return rows

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for row in self.status():
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        return counts

    @staticmethod
    def _summary(counts: dict[str, int]) -> str:
        return " ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "empty"

    def describe(self) -> str:
        rows = self.status()
        width = max(len(r["label"]) for r in rows)
        lines = []
        for r in rows:
            extra = ""
            if r["holder"]:
                extra = f"  pid {r['holder']['pid']} {r['holder']['label']}"
            elif r.get("last_error"):
                extra = f"  {r['last_error']}"
            age = f"{(time.time() - r['since']) / 60:.0f}m" if r.get("since") else ""
            lines.append(f"  {r['label']:<{width}}  {r['account_id']}  {r['state']:<11} {age:>5}{extra}")
        return "\n".join(lines)


def teardown_clean(run_dir: Path) -> bool | None:
    """Whether a run that ended early (interrupt, exception) still tore down cleanly.

    The coordinator's abort path writes ``run.json`` with its cleanup result; a clean leak
    check there means the account can be leased again. None when nothing can be proven."""
    try:
        data = json.loads((run_dir / "run.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None
    cleanup = data.get("cleanup") or {}
    leak = cleanup.get("leak_check") if isinstance(cleanup, dict) else None
    if not isinstance(leak, dict) or "leaked" not in leak:
        return None
    if data.get("cleanup_errors"):
        return False
    return not leak["leaked"]
