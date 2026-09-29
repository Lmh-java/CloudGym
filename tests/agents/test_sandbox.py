"""Sandbox argv: the workspace is the only host directory the agent sees, at a neutral path."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from harness.agents.base import AgentCall
from harness.agents.claude import ClaudeAdapter
from harness.agents.sandbox import Sandbox, available, bwrap_argv, default_sandbox, selftest


class BwrapArgvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "run" / "private" / "agent-workspace"
        self.workspace.mkdir(parents=True)
        self.home = self.root / "home"
        (self.home / ".claude").mkdir(parents=True)
        (self.home / ".claude.json").write_text("{}")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_workspace_mounted_at_neutral_path_and_home_is_tmpfs(self) -> None:
        sandbox = default_sandbox(self.workspace, home=self.home)
        argv = bwrap_argv(sandbox, ["claude", "-p", "hi"])
        self.assertEqual(argv[0], "bwrap")
        joined = " ".join(argv)
        self.assertIn(f"--bind {self.workspace.resolve()} /work --chdir /work", joined)
        self.assertIn("--tmpfs /home", joined)
        self.assertIn(f"--setenv HOME {self.home}", joined)
        self.assertIn("--unshare-pid", joined)
        self.assertIn("--die-with-parent", joined)
        self.assertNotIn("--unshare-net", joined)
        self.assertEqual(argv[argv.index("--") + 1:], ["claude", "-p", "hi"])

    def test_agent_state_bound_writable_only_when_present(self) -> None:
        sandbox = default_sandbox(self.workspace, home=self.home)
        joined = " ".join(bwrap_argv(sandbox, ["x"]))
        self.assertIn(f"--bind {self.home / '.claude'} {self.home / '.claude'}", joined)
        self.assertIn(f"--bind {self.home / '.claude.json'} {self.home / '.claude.json'}", joined)
        self.assertNotIn(".codex", joined)          # absent on this host: not bound, not an error

    def test_run_directory_itself_is_not_bound(self) -> None:
        # The run dir (result.json, private/, snapshots) sits right above the workspace
        # and must not be reachable: only the workspace path appears as a bind source.
        sandbox = default_sandbox(self.workspace, home=self.home,
                                  rw_binds=[self.root / "cache"], ro_binds=[self.root / "venv"])
        (self.root / "cache").mkdir()
        (self.root / "venv").mkdir()
        argv = bwrap_argv(sandbox, ["x"])
        sources = [argv[i + 1] for i, a in enumerate(argv) if a in ("--bind", "--ro-bind")]
        self.assertNotIn(str(self.root / "run"), sources)
        self.assertIn(str(self.root / "cache"), sources)
        self.assertIn(str(self.root / "venv"), sources)

    def test_runner_refuses_sandbox_for_another_cwd(self) -> None:
        import asyncio

        from harness.agents.runner import AgentRunner

        other = self.root / "other"
        other.mkdir()
        sandbox = Sandbox(workspace=self.workspace, home=self.home)
        call = AgentCall(provider="claude", prompt="x", cwd=other, sandbox=sandbox, timeout=5)
        with self.assertRaises(ValueError):
            asyncio.run(AgentRunner(adapters=[ClaudeAdapter()]).run(call))


@unittest.skipUnless(available(), "bubblewrap not available on this host")
class BwrapLiveTests(unittest.TestCase):
    """Only where bwrap runs (the ops VM, Linux CI): the self-test hides what it must."""

    def test_selftest_hides_host_paths_and_exposes_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "ws"
            workspace.mkdir()
            secret = root / "secret"
            secret.mkdir()
            sandbox = default_sandbox(workspace, home=root / "home")
            result = selftest(sandbox, [secret, Path.home()])
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["visible"], [])

    def test_selftest_reports_a_visible_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "ws"
            workspace.mkdir()
            sandbox = default_sandbox(workspace, home=root / "home")
            result = selftest(sandbox, [Path("/usr/bin")])
            self.assertFalse(result["ok"])
            self.assertEqual(result["visible"], ["/usr/bin"])

    def test_agent_sees_workspace_as_work_and_nothing_of_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "ws"
            workspace.mkdir()
            (workspace / "hello.txt").write_text("hi\n")
            sandbox = default_sandbox(workspace, home=root / "home")
            # The real home (its dotfiles, the working tree) is gone; the sandbox home is an
            # empty directory; the workspace is the cwd under its neutral name.
            probe = f"pwd; cat hello.txt; ls -A {sandbox.home} | wc -l; ls {os.path.expanduser('~')} 2>&1 | head -1"
            argv = bwrap_argv(sandbox, ["/bin/sh", "-c", probe])
            out = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout.splitlines()
            self.assertEqual(out[0], "/work")
            self.assertEqual(out[1], "hi")
            self.assertEqual(out[2].strip(), "0")
            self.assertIn("No such file", out[3])


if __name__ == "__main__":
    unittest.main()


class SessionOverlayTests(unittest.TestCase):
    def test_each_cell_gets_its_own_session_stores_after_the_shared_state(self) -> None:
        import tempfile
        from harness.agents.sandbox import SESSION_DIRS, Sandbox, bwrap_argv, default_sandbox
        with tempfile.TemporaryDirectory() as d:
            home, cell = Path(d) / "home", Path(d) / "run" / "private" / "agent-sessions"
            (home / ".claude").mkdir(parents=True)
            (home / ".codex").mkdir()
            ws = Path(d) / "ws"; ws.mkdir()
            sb = default_sandbox(ws, home=home, session_root=cell)
            targets = [str(t) for _, t in sb.overlays]
            self.assertEqual(targets, [str(home / rel) for rel in SESSION_DIRS])
            argv = bwrap_argv(sb, ["true"])
            state = argv.index(str(home / ".claude"))
            projects = argv.index(str(home / ".claude/projects"))
            self.assertLess(state, projects, "the overlay is bound over the shared state, not under it")
            self.assertEqual(argv[projects - 1], str(cell / ".claude__projects"))
            self.assertEqual(default_sandbox(ws, home=home).overlays, ())      # opt-in

