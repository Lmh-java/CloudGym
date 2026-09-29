"""Detached batch execution: ``<batch>/daemon.pid`` + ``<batch>/daemon.log``.

``bench start`` launches ``bench run`` in its own session so it survives the
terminal, the editor and any agent session that spawned it; ``bench stop``
sends it SIGINT (the Ctrl+C path: the ledger is updated and AWS is torn down)
and waits for it to exit. On macOS a ``caffeinate -i -w <pid>`` sidecar keeps
the machine from idle-sleeping for exactly as long as the batch runs.

Only the pid file is authoritative: a pid whose process is gone is *stale* and
is cleared by the next ``start``/``stop``. Nothing here reads the ledger.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from harness.procutil import pid_alive

PID_FILE = "daemon.pid"
LOG_FILE = "daemon.log"


class DaemonError(RuntimeError):
    pass


@dataclass(frozen=True)
class DaemonState:
    batch_dir: Path
    pid: int | None            # what the pid file says (None: no pid file)
    alive: bool

    @property
    def log_path(self) -> Path:
        return self.batch_dir / LOG_FILE

    @property
    def pid_path(self) -> Path:
        return self.batch_dir / PID_FILE

    @property
    def stale(self) -> bool:
        return self.pid is not None and not self.alive

    def describe(self) -> str:
        if self.alive:
            return f"running (pid {self.pid}, log {self.log_path})"
        if self.stale:
            return f"exited (was pid {self.pid}; see {self.log_path})"
        return "not running"


def read_pid(batch_dir: Path) -> int | None:
    path = batch_dir / PID_FILE
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def daemon_state(batch_dir: Path) -> DaemonState:
    pid = read_pid(batch_dir)
    return DaemonState(batch_dir, pid, pid is not None and pid_alive(pid))


def clear_stale(batch_dir: Path) -> None:
    state = daemon_state(batch_dir)
    if state.stale:
        state.pid_path.unlink(missing_ok=True)


def start_daemon(argv: list[str], batch_dir: Path, *, cwd: Path | None = None,
                 caffeinate: bool = True, settle: float = 3.0) -> DaemonState:
    """Run ``argv`` detached, logging to ``daemon.log`` and recording its pid.

    Refuses when a daemon for ``batch_dir`` is still alive. Waits up to
    ``settle`` seconds and raises (with the log tail) if the process already
    exited, so a bad flag or expired credentials fail at the prompt, not
    silently in a log file.
    """
    state = daemon_state(batch_dir)
    if state.alive:
        raise DaemonError(f"batch already {state.describe()}; `bench stop` it first")
    batch_dir.mkdir(parents=True, exist_ok=True)
    state.pid_path.unlink(missing_ok=True)

    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with state.log_path.open("ab") as log:
        log.write(f"\n=== {stamp} start: {' '.join(argv)}\n".encode())
        log.flush()
        proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    state.pid_path.write_text(f"{proc.pid}\n")
    if caffeinate and shutil.which("caffeinate"):
        subprocess.Popen(["caffeinate", "-i", "-w", str(proc.pid)], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            state.pid_path.unlink(missing_ok=True)
            raise DaemonError(f"exited immediately with status {proc.returncode}:\n{log_tail(batch_dir)}")
        time.sleep(0.1)
    return daemon_state(batch_dir)


def stop_daemon(batch_dir: Path, *, timeout: float = 900.0, sig: int = signal.SIGINT,
                log=lambda _m: None) -> DaemonState:
    """SIGINT the daemon (graceful: ledger + AWS teardown) and wait for it to exit."""
    state = daemon_state(batch_dir)
    if not state.alive:
        clear_stale(batch_dir)
        return daemon_state(batch_dir)
    assert state.pid is not None
    os.kill(state.pid, sig)
    log(f"sent {signal.Signals(sig).name} to pid {state.pid}; waiting up to {timeout:g}s for teardown")
    deadline = time.monotonic() + timeout
    next_note = time.monotonic() + 15
    while pid_alive(state.pid):
        if time.monotonic() >= deadline:
            return daemon_state(batch_dir)
        if time.monotonic() >= next_note:
            log(f"  still running (pid {state.pid}); tail -f {state.log_path}")
            next_note += 30
        time.sleep(0.2)
    clear_stale(batch_dir)
    return daemon_state(batch_dir)


def log_tail(batch_dir: Path, lines: int = 20) -> str:
    path = batch_dir / LOG_FILE
    if not path.is_file():
        return ""
    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])


def follow_log(batch_dir: Path, lines: int, follow: bool) -> int:
    """Hand the terminal to ``tail`` (exec: Ctrl+C ends it cleanly)."""
    path = batch_dir / LOG_FILE
    if not path.is_file():
        print(f"no {LOG_FILE} under {batch_dir}", file=sys.stderr)
        return 1
    argv = ["tail", "-n", str(lines)] + (["-f"] if follow else []) + [str(path)]
    os.execvp(argv[0], argv)
