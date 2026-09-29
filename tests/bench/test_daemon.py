"""Detached batch lifecycle: pid file, refusal while alive, graceful stop, stale cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from harness.bench import DaemonError, daemon_state, start_daemon, stop_daemon
from harness.bench.daemon import LOG_FILE, PID_FILE

# Stand-in for `bench run`: prints, then sleeps until SIGINT, which it handles
# the way the runner does (finish bookkeeping, exit 130).
CHILD = textwrap.dedent("""
    import signal, sys, time
    print("child up", flush=True)
    try:
        while True:
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("child interrupted; teardown", flush=True)
        sys.exit(130)
""")


class DaemonTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.batch_dir = Path(self._temp.name) / "batch"
        self.argv = [sys.executable, "-c", CHILD]

    def tearDown(self) -> None:
        pid = daemon_state(self.batch_dir).pid
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self._temp.cleanup()

    def test_start_stop_roundtrip(self) -> None:
        state = start_daemon(self.argv, self.batch_dir, caffeinate=False, settle=0.3)
        self.assertTrue(state.alive)
        self.assertEqual(int((self.batch_dir / PID_FILE).read_text()), state.pid)
        self.assertEqual(os.getsid(state.pid), state.pid, "runs in its own session")
        with self.assertRaises(DaemonError):
            start_daemon(self.argv, self.batch_dir, caffeinate=False, settle=0.1)

        notes: list[str] = []
        stopped = stop_daemon(self.batch_dir, timeout=10, log=notes.append)
        self.assertFalse(stopped.alive)
        self.assertIsNone(stopped.pid, "pid file cleared after a clean stop")
        log = (self.batch_dir / LOG_FILE).read_text()
        self.assertIn("child up", log)
        self.assertIn("child interrupted; teardown", log)
        self.assertIn("start:", log.splitlines()[1])
        self.assertTrue(notes and notes[0].startswith("sent SIGINT"))

    def test_immediate_exit_surfaces_log(self) -> None:
        bad = [sys.executable, "-c", "import sys; print('bad flag'); sys.exit(2)"]
        with self.assertRaises(DaemonError) as ctx:
            start_daemon(bad, self.batch_dir, caffeinate=False, settle=1.0)
        self.assertIn("status 2", str(ctx.exception))
        self.assertIn("bad flag", str(ctx.exception))
        self.assertFalse((self.batch_dir / PID_FILE).exists())

    def test_stale_pid_is_reported_then_cleared(self) -> None:
        self.batch_dir.mkdir(parents=True)
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        (self.batch_dir / PID_FILE).write_text(f"{dead.pid}\n")
        state = daemon_state(self.batch_dir)
        self.assertTrue(state.stale)
        self.assertIn("exited", state.describe())
        self.assertFalse(stop_daemon(self.batch_dir).stale)
        self.assertFalse((self.batch_dir / PID_FILE).exists())
        # a fresh start replaces the stale record
        state = start_daemon(self.argv, self.batch_dir, caffeinate=False, settle=0.3)
        self.assertTrue(state.alive)

    def test_stop_timeout_leaves_it_running(self) -> None:
        stubborn = [sys.executable, "-c", "import signal, time; signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
                    "while True: time.sleep(0.05)"]
        state = start_daemon(stubborn, self.batch_dir, caffeinate=False, settle=0.3)
        after = stop_daemon(self.batch_dir, timeout=0.5)
        self.assertTrue(after.alive)
        self.assertEqual(after.pid, state.pid)
