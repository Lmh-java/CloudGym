"""Process helpers shared by the bench daemon and the sandbox pool."""

from __future__ import annotations

import os


def pid_alive(pid: int) -> bool:
    """Whether ``pid`` is running. Reaps it first if it is our own finished child, since
    ``kill(pid, 0)`` would otherwise report a zombie as alive."""
    try:
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            return False
    except ChildProcessError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:      # exists, owned by someone else
        return True
    return True
