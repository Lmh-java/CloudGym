"""Filesystem confinement for an agent under test (bubblewrap).

An agent CLI launched by the harness runs as the harness's own uid, so without
confinement it can read anything the harness can: the published cases (reference
answers, interference designs), other cells' results, the harness's own run files.
On 2026-09-21 the paper-config-1 transcripts showed agents doing exactly that.

The sandbox is a bubblewrap mount namespace: the host's system tree read-only, a fresh
tmpfs for ``/tmp`` and ``/home``, the agent CLIs' own state directories bound in, and
the agent's workspace bound at a neutral path (``/work``) so nothing about the run
(batch, arm, case) shows in the cwd. Everything else does not exist inside. Network is
shared (AWS, the MCP server on localhost); the PID namespace is separate so a timeout
kills the whole tree.

Linux only. ``available()`` is False elsewhere and the caller decides whether that is
acceptable (``auto``) or fatal (``required``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

MOUNT_POINT = "/work"

# Host directories every sandbox gets read-only. /etc carries resolv.conf (a symlink into
# /run/systemd/resolve on Ubuntu, bound separately), CA certificates and passwd.
SYSTEM_RO = ("/usr", "/etc", "/opt", "/var/lib/dpkg", "/run/systemd/resolve")
# Ubuntu's merged-usr layout: these are symlinks on the host and stay symlinks inside.
USR_SYMLINKS = ("lib", "lib64", "bin", "sbin", "lib32", "libx32")
# Where the agent CLIs keep other sessions' records under their (shared, bound) state dirs:
# transcripts, shell snapshots, file backups, todos. Each cell gets its own empty copy of
# every one, bound over the shared directory, so an agent can never read another cell's
# session (every cell runs in /work, so Claude filed them all under one project). Logins
# and settings stay shared.
SESSION_DIRS = (".claude/projects", ".claude/sessions", ".claude/session-env", ".claude/shell-snapshots",
                ".claude/file-history", ".claude/todos", ".codex/sessions", ".codex/shell_snapshots")


@dataclass(frozen=True)
class Sandbox:
    """What one agent process may see."""

    workspace: Path
    home: Path
    # Host paths bound at the same path, writable (agent CLI state, the agents' plugin cache).
    rw_binds: tuple[Path, ...] = ()
    # Host paths bound at the same path, read-only (a Python env the agent's PATH points at).
    ro_binds: tuple[Path, ...] = ()
    # (host source, path inside) bound writable after rw_binds: per-cell session stores.
    overlays: tuple[tuple[Path, Path], ...] = ()
    mount_point: str = MOUNT_POINT
    executable: str = "bwrap"

    def describe(self) -> dict:
        return {"backend": "bwrap", "workspace_mount": self.mount_point, "home": str(self.home),
                "rw_binds": [str(p) for p in self.rw_binds], "ro_binds": [str(p) for p in self.ro_binds],
                "overlays": [str(dst) for _, dst in self.overlays]}


def available(executable: str = "bwrap") -> bool:
    return sys.platform == "linux" and shutil.which(executable) is not None


def bwrap_argv(sandbox: Sandbox, inner: Sequence[str]) -> list[str]:
    """The full command line: bubblewrap options, ``--``, then the agent's own argv."""
    argv: list[str] = [sandbox.executable]
    for path in SYSTEM_RO:
        if os.path.exists(path):
            argv += ["--ro-bind", path, path]
    for name in USR_SYMLINKS:
        if os.path.islink(f"/{name}"):
            argv += ["--symlink", f"usr/{name}", f"/{name}"]
    argv += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root",
             "--dir", str(sandbox.home)]
    for path in sandbox.ro_binds:
        if path.exists():
            argv += ["--ro-bind", str(path), str(path)]
    for path in sandbox.rw_binds:
        if path.exists():
            argv += ["--bind", str(path), str(path)]
    for source, target in sandbox.overlays:          # after the state dirs they cover
        if source.exists():
            argv += ["--bind", str(source), str(target)]
    argv += ["--bind", str(sandbox.workspace), sandbox.mount_point, "--chdir", sandbox.mount_point,
             "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
             "--setenv", "HOME", str(sandbox.home), "--setenv", "PWD", sandbox.mount_point,
             "--"]
    argv.extend(inner)
    return argv


def default_sandbox(workspace: Path, *, home: Path | None = None, rw_binds: Sequence[Path] = (),
                    ro_binds: Sequence[Path] = (), session_root: Path | None = None) -> Sandbox:
    """The agents' state directories plus whatever the caller adds.

    Claude Code keeps credentials, settings and session logs in ``~/.claude`` and
    ``~/.claude.json``; Codex in ``~/.codex``. Both are bound writable so the CLIs behave as
    on the host (and stay logged in). The Python interpreter the agent's PATH resolves to
    is typically the harness's uv-managed one: the caller passes the venv and the uv
    installation as read-only binds so ``python3``/boto3 keep working; the venv's editable
    install of the harness package resolves to a path that does not exist inside.
    """
    home = Path(home or os.environ.get("HOME") or Path.home())
    state = [home / ".claude", home / ".claude.json", home / ".codex"]
    overlays = []
    if session_root is not None:
        # ``session_root`` is the cell's private dir (never visible inside): one empty store per
        # SESSION_DIRS entry whose agent state dir exists on this host.
        for rel in SESSION_DIRS:
            if not (home / rel.split("/")[0]).is_dir():
                continue
            source = Path(session_root) / rel.replace("/", "__")
            source.mkdir(parents=True, exist_ok=True)
            (home / rel).mkdir(parents=True, exist_ok=True)        # the mount point
            overlays.append((source, home / rel))
    return Sandbox(workspace=workspace.resolve(), home=home,
                   rw_binds=tuple(state) + tuple(Path(p) for p in rw_binds),
                   ro_binds=tuple(Path(p) for p in ro_binds), overlays=tuple(overlays))


def selftest(sandbox: Sandbox, hidden: Sequence[Path], *, timeout: float = 30.0) -> dict:
    """Prove the sandbox hides ``hidden`` and exposes the workspace, from inside it.

    Returns ``{"ok": bool, "visible": [...], "workspace": bool, "error": str | None}``. A
    path in ``visible`` exists inside the sandbox although it must not; the caller treats
    ``ok=False`` as fatal so a misconfigured sandbox never runs an agent unconfined.
    """
    script = "\n".join(
        [f'test -e {_sh(str(p))} && echo "VISIBLE {p}"' for p in hidden]
        + [f'test -d {sandbox.mount_point} && test -w {sandbox.mount_point} && echo WORKSPACE_OK', "exit 0"])
    argv = bwrap_argv(sandbox, ["/bin/sh", "-c", script])
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "visible": [], "workspace": False, "error": f"{type(exc).__name__}: {exc}"}
    visible = [line[len("VISIBLE "):] for line in proc.stdout.splitlines() if line.startswith("VISIBLE ")]
    workspace_ok = "WORKSPACE_OK" in proc.stdout.splitlines()
    error = None
    if proc.returncode != 0:
        error = f"bwrap exited {proc.returncode}: {proc.stderr.strip()[:500]}"
    return {"ok": not visible and workspace_ok and error is None, "visible": visible,
            "workspace": workspace_ok, "error": error}


def _sh(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
