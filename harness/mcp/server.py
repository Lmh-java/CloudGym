"""MCP tools exposed to the evaluated agent.

The agent-facing surface is deliberately tiny: one ``finish`` tool. The agent
acts on the cloud with its own credentials and tools; the harness only
observes, distracts, evaluates, and cleans up.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager
from typing import Any

from harness.awareness import (AWARENESS_LEVELS,  # noqa: F401  (re-exported)
                               CONSULT_REQUIRES_LANDED)
from harness.runtime.coordinator import RuntimeCoordinator


def create_server(coordinator: RuntimeCoordinator, *, manage_lifecycle: bool = True,
                  awareness: str = "none"):
    """Build the ``MCPServer``.

    With ``manage_lifecycle=True`` (the standalone ``cloudgym-runtime`` CLI)
    the server's lifespan starts and aborts the coordinator. The in-process
    ``run-case`` driver passes ``False`` and owns start/finish ordering itself.

    ``awareness`` selects what the agent can learn about other principals:

    * ``none``       only ``finish`` is registered.
    * ``observed``   ``changes`` returns a roster of the other principals with
                     their role, responsibility and intent, available from the
                     start — but not what they have done.
    * ``disclosed``  ``changes`` additionally lists the API calls other
                     principals have made, once they have happened.
    * ``consult_open``  the same, with every principal answering whenever asked — the
                     control that separates a failure to acquire the policy from a question
                     asked before the principal would speak.
    * ``consult``    the resolution policy is withheld from the prompt (see
                     ``harness.runtime.case.agent_prompt``) and ``ask_devops`` puts a
                     question to the team channel. Only a principal who has already
                     touched the state being asked about answers, so the reconciliation
                     is reachable after the conflict exists rather than before. No
                     roster, no change list: the tool cannot be used to discover that
                     anything happened.
    """
    if awareness not in AWARENESS_LEVELS:
        raise ValueError(f"awareness must be one of {AWARENESS_LEVELS}")
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as exc:  # pragma: no cover - installation diagnostic
        raise RuntimeError("install the pinned 'mcp' dependency to run the MCP server") from exc

    @asynccontextmanager
    async def lifespan(_server):
        if manage_lifecycle:
            await coordinator.start()
        try:
            yield None
        finally:
            if manage_lifecycle:
                await coordinator.abort()

    mcp = MCPServer("CloudGym AWS Runtime", lifespan=lifespan)

    @mcp.tool()
    async def finish() -> dict[str, Any]:
        """Declare the task complete. Call exactly once, after your last cloud change.

        The harness then captures the final cloud state, evaluates it, and
        tears the environment down. Nothing you do after calling it counts.
        """
        # Evaluation and teardown take minutes; run them in the background so
        # the tool call returns before the client times out. The agent only
        # needs to know the request was accepted.
        already = coordinator.finished
        coordinator.request_finish()
        return {"run_id": coordinator.config.run_id, "accepted": True,
                "already_finished": already}

    if awareness == "observed":
        @mcp.tool()
        async def changes() -> dict[str, Any]:
            """Who else operates on this account.

            Returns the other principals — their role, responsibility and
            intent — but not what they have done.
            """
            controller = coordinator.controller
            return {"principals": controller.roster() if controller else []}

    elif awareness == "disclosed":
        @mcp.tool()
        async def changes() -> dict[str, Any]:
            """Who else operates on this account and what they have changed.

            Returns the other principals — their role, responsibility and
            intent — and the API calls they have made so far, oldest first.
            Call it whenever you want to check what else has changed.
            """
            controller = coordinator.controller
            return {
                "principals": controller.roster() if controller else [],
                "changes": controller.distractor_activity() if controller else [],
            }

    elif awareness in ("consult", "consult_open"):
        # The agent-facing surface is identical for both levels by design — same tool, same
        # description, same withheld policy. Only `require_landed` differs, so a verdict
        # difference between them is attributable to the ordering gate alone.
        require_landed = awareness in CONSULT_REQUIRES_LANDED

        @mcp.tool()
        async def ask_devops(about: str = "", question: str = "", thread: str = "") -> dict[str, Any]:
            """Post a question to the platform team's channel, or re-read a thread.

            The people on the other end own the shared infrastructure in this account.
            Only ask when you found a problem, not general questions. Be specific: name
            the resources involved — identifiers, names, the values you saw on them — in
            `about`, and put the question itself in `question`. Both are read. A general
            question about conventions gets no answer.

            Every question opens a thread and returns its id. Replies that arrive after
            you asked are delivered with your next call, under `earlier_threads`, and you
            can re-read one thread at any time by passing its `thread` id alone. Silence
            on a thread means nobody has answered it yet — nothing more.
            """
            replies = coordinator.consult(about, question, thread or None, require_landed=require_landed)
            replies["question"] = question
            return replies

    return mcp


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _embedded_server_class():
    """A uvicorn Server that leaves the process's signal handlers alone.

    ``uvicorn.Server.serve`` installs its own SIGINT/SIGTERM handlers (``capture_signals``,
    or ``install_signal_handlers`` in older releases). Embedded in the bench daemon that
    replaced asyncio's Ctrl+C handling, so ``bench stop`` only told one in-process MCP or
    proxy server to exit while the batch carried on (2026-09-08). The owning process
    decides how to stop; these servers are stopped through ``should_exit``."""
    import contextlib
    import uvicorn

    class EmbeddedServer(uvicorn.Server):
        @contextlib.contextmanager
        def capture_signals(self):
            yield

        def install_signal_handlers(self) -> None:
            pass

    return EmbeddedServer


class _LazyEmbeddedServer:
    def __call__(self, config):
        return _embedded_server_class()(config)


_EmbeddedServer = _LazyEmbeddedServer()


class BackgroundServer:
    """Serve an ``MCPServer`` (or any ASGI app) inside the running loop."""

    def __init__(self, server=None, *, app=None, host: str = "127.0.0.1", port: int | None = None,
                 path: str = "/mcp"):
        if (server is None) == (app is None):
            raise ValueError("pass exactly one of server= or app=")
        self.server = server
        self.app = app
        self.host = host
        self.port = port or free_port(host)
        self.path = path if server is not None else ""
        self._uvicorn = None
        self._task: asyncio.Task[None] | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{self.path}"

    async def __aenter__(self) -> "BackgroundServer":
        import uvicorn

        app = self.app if self.app is not None else self.server.streamable_http_app(
            streamable_http_path=self.path, json_response=True)
        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning", lifespan="on")
        self._uvicorn = _EmbeddedServer(config)
        self._task = asyncio.create_task(self._uvicorn.serve(), name="cloudgym-mcp")
        while not self._uvicorn.started:
            if self._task.done():
                self._task.result()
                raise RuntimeError("MCP server exited before starting")
            await asyncio.sleep(0.05)
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            except Exception:
                pass
