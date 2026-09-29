"""Async process orchestration for provider-specific headless agent CLIs."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Iterable

from ..aws_env import scrubbed_environment
from .base import AgentAdapter, AgentCall, AgentResult
from .claude import ClaudeAdapter
from .codex import CodexAdapter
from .transcript import TranscriptRenderer


SCRATCH_DIR = ".cloudgym-agent"


class AgentRunnerError(RuntimeError):
    def __init__(self, message: str, *, provider: str, exit_code: int | None = None, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.provider, self.exit_code, self.stdout, self.stderr = provider, exit_code, stdout, stderr


class AgentTimeoutError(AgentRunnerError):
    """Raised on timeout; ``partial`` carries whatever accounting was streamed."""

    def __init__(self, message: str, *, provider: str, stdout: str = "", stderr: str = "",
                 partial: AgentResult | None = None):
        super().__init__(message, provider=provider, stdout=stdout, stderr=stderr)
        self.partial = partial


def _descendants(pid: int) -> list[tuple[int, str]]:
    """(pid, comm) of every process below ``pid`` (Linux /proc; empty elsewhere)."""
    children: dict[int, list[tuple[int, str]]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8", errors="replace") as handle:
                stat = handle.read()
        except OSError:
            continue
        comm = stat[stat.index("(") + 1:stat.rindex(")")]
        ppid = int(stat[stat.rindex(")") + 2:].split()[1])
        children.setdefault(ppid, []).append((int(entry), comm))
    found: list[tuple[int, str]] = []
    stack = [pid]
    while stack:
        for child in children.get(stack.pop(), []):
            found.append(child)
            stack.append(child[0])
    return found


async def _terminate(process: asyncio.subprocess.Process, *, sandboxed: bool = False) -> None:
    if process.returncode is not None:
        return
    try:
        if sandboxed:
            # bwrap is init of the agent's PID namespace: SIGTERM to it tears the namespace
            # down (SIGKILL to everything inside) before the CLI can flush its final result
            # event. Signal the agent's own processes; bwrap exits with the command's status.
            for pid, comm in _descendants(process.pid):
                if comm != "bwrap":
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2)
    except TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()


class AgentRunner:
    def __init__(self, adapters: Iterable[AgentAdapter] | None = None, *, max_concurrency: int | None = None):
        values = adapters or (CodexAdapter(), ClaudeAdapter())
        self.adapters = {adapter.provider: adapter for adapter in values}
        self.max_concurrency = max_concurrency

    async def run(self, call: AgentCall) -> AgentResult:
        try:
            adapter = self.adapters[call.provider]
        except KeyError as exc:
            raise AgentRunnerError(f"unsupported agent provider: {call.provider}", provider=call.provider) from exc
        if call.timeout <= 0:
            raise ValueError("timeout must be positive")
        cwd = Path(call.cwd or Path.cwd()).resolve()
        if not cwd.is_dir():
            raise ValueError(f"agent cwd is not a directory: {cwd}")
        env = dict(os.environ) if call.inherit_env else scrubbed_environment()
        env.update(call.env)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="cloudgym-agent-") as temp:
            temp_path = Path(temp)
            # Codex reads its output schema and writes its last message through files. Inside
            # a sandbox only the workspace is shared with the host, so they live in a hidden
            # scratch directory there (removed after the run) and the CLI sees them under
            # the mount point.
            scratch = cwd / SCRATCH_DIR if call.sandbox is not None else temp_path
            inner_scratch = (PurePosixPath(call.sandbox.mount_point) / SCRATCH_DIR
                             if call.sandbox is not None else PurePosixPath(temp_path))
            wants_schema = call.output_schema is not None and call.provider == "codex"
            wants_output = call.provider == "codex"
            if call.sandbox is not None and (wants_schema or wants_output):
                scratch.mkdir(parents=True, exist_ok=True)
            schema_path = scratch / "schema.json" if wants_schema else None
            output_path = scratch / "last-message.txt" if wants_output else None
            if schema_path:
                schema_path.write_text(json.dumps(call.output_schema), encoding="utf-8")
            argv = adapter.command(call, schema_path=Path(inner_scratch / "schema.json") if schema_path else None,
                                   output_path=Path(inner_scratch / "last-message.txt") if output_path else None)
            if call.sandbox is not None:
                from .sandbox import bwrap_argv

                if Path(call.sandbox.workspace) != cwd:
                    raise ValueError(f"sandbox workspace {call.sandbox.workspace} is not the agent cwd {cwd}")
                argv = bwrap_argv(call.sandbox, argv)
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv, cwd=cwd, env=env, stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                    # stream-json events are one line per message; a tool result that
                    # embeds a large file blows through asyncio's 64KB default and
                    # readline() raises ValueError, killing the run mid-stream.
                    limit=32 * 1024 * 1024,
                )
            except OSError as exc:
                raise AgentRunnerError(str(exc), provider=call.provider) from exc
            try:
                if call.streaming:
                    return await self._run_streaming(adapter, call, process, started, output_path)
                return await self._run_buffered(adapter, call, process, started, output_path)
            finally:
                if call.sandbox is not None:
                    shutil.rmtree(cwd / SCRATCH_DIR, ignore_errors=True)

    async def _run_buffered(self, adapter: AgentAdapter, call: AgentCall, process: asyncio.subprocess.Process,
                        started: float, output_path: Path | None) -> AgentResult:
        try:
            input_data = call.prompt.encode() if adapter.prompt_via_stdin else None
            stdout_b, stderr_b = await asyncio.wait_for(process.communicate(input_data), timeout=call.timeout)
        except asyncio.CancelledError:
            await _terminate(process, sandboxed=call.sandbox is not None)
            stdout_b, stderr_b = await process.communicate()
            raise
        except TimeoutError:
            await _terminate(process, sandboxed=call.sandbox is not None)
            stdout_b, stderr_b = await process.communicate()
            raise AgentTimeoutError(f"{call.provider} timed out after {call.timeout}s", provider=call.provider, stdout=stdout_b.decode(errors="replace"), stderr=stderr_b.decode(errors="replace"))
        stdout, stderr = stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")
        if process.returncode != 0:
            raise AgentRunnerError(f"{call.provider} exited with status {process.returncode}", provider=call.provider, exit_code=process.returncode, stdout=stdout, stderr=stderr)
        output_text = output_path.read_text(encoding="utf-8") if output_path and output_path.exists() else None
        try:
            result = adapter.parse(call, stdout=stdout, stderr=stderr, output_text=output_text)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AgentRunnerError(f"invalid {call.provider} output: {exc}", provider=call.provider, stdout=stdout, stderr=stderr) from exc
        return AgentResult(**{**result.__dict__, "duration_seconds": time.monotonic() - started})

    async def _run_streaming(self, adapter: AgentAdapter, call: AgentCall, process: asyncio.subprocess.Process,
                             started: float, output_path: Path | None) -> AgentResult:
        """Consume the agent's event stream line by line, journaling as it arrives."""
        assert call.transcript_dir is not None
        transcript_dir = Path(call.transcript_dir)
        transcript_dir.mkdir(parents=True, exist_ok=True)
        events_path = transcript_dir / "events.jsonl"
        renderer = TranscriptRenderer(transcript_dir, provider=call.provider)
        events: list[dict] = []
        stderr_chunks: list[bytes] = []

        async def drain_stderr() -> None:
            assert process.stderr is not None
            while True:
                chunk = await process.stderr.read(65536)
                if not chunk:
                    return
                stderr_chunks.append(chunk)

        stderr_task = asyncio.create_task(drain_stderr())
        if adapter.prompt_via_stdin:
            assert process.stdin is not None
            process.stdin.write(call.prompt.encode())
            await process.stdin.drain()
            process.stdin.close()
        elif process.stdin is not None:
            process.stdin.close()

        timed_out = False
        deadline = started + call.timeout
        assert process.stdout is not None
        with open(events_path, "a", encoding="utf-8") as events_file:
            async def read_until_eof(limit: float | None) -> None:
                nonlocal timed_out
                while True:
                    remaining = None if limit is None else limit - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        timed_out = True
                        return
                    try:
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=remaining)
                    except TimeoutError:
                        timed_out = True
                        return
                    if not line:
                        return
                    text = line.decode(errors="replace")
                    events_file.write(text if text.endswith("\n") else text + "\n")
                    events_file.flush()
                    stripped = text.strip()
                    if not stripped:
                        continue
                    try:
                        event = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(event, dict):
                        events.append(event)
                        try:
                            renderer.feed(event)
                        except Exception:  # noqa: BLE001 - rendering must never break the run
                            pass

            try:
                await read_until_eof(deadline)
                if timed_out:
                    # Kill, but keep reading: the CLI flushes a final result
                    # event on SIGTERM and dropping it would lose accounting.
                    await _terminate(process, sandboxed=call.sandbox is not None)
                    await read_until_eof(time.monotonic() + 5)
                await process.wait()
            except asyncio.CancelledError:
                await _terminate(process, sandboxed=call.sandbox is not None)
                raise
            finally:
                # Never let stderr draining mask the real outcome: if the pipe is
                # still open (process alive after an exception), cancel the drain
                # instead of raising a bare TimeoutError out of the finally.
                if not stderr_task.done():
                    try:
                        await asyncio.wait_for(stderr_task, timeout=5)
                    except (TimeoutError, asyncio.CancelledError):
                        stderr_task.cancel()
                renderer.close()
        stderr = b"".join(stderr_chunks).decode(errors="replace")
        output_text = output_path.read_text(encoding="utf-8") if output_path and output_path.exists() else None
        try:
            result = adapter.parse_stream(call, events=events, stderr=stderr, output_text=output_text)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AgentRunnerError(f"invalid {call.provider} output: {exc}", provider=call.provider, stderr=stderr) from exc
        result = AgentResult(**{
            **result.__dict__,
            "duration_seconds": time.monotonic() - started,
            "exit_code": process.returncode if process.returncode is not None else -1,
            "events_path": events_path,
            "transcript_path": transcript_dir / "transcript.md",
            "turns_path": transcript_dir / "turns.jsonl",
            "tool_calls": renderer.tool_calls,
            "model": result.model or renderer.model,
            "session_id": result.session_id or renderer.session_id,
            "num_turns": result.num_turns if result.num_turns is not None else (renderer.turns or None),
            "partial": result.partial or timed_out,
        })
        if timed_out:
            raise AgentTimeoutError(f"{call.provider} timed out after {call.timeout}s", provider=call.provider,
                                    stderr=stderr, partial=result)
        if process.returncode != 0:
            raise AgentRunnerError(f"{call.provider} exited with status {process.returncode}", provider=call.provider,
                                   exit_code=process.returncode, stderr=stderr)
        return result

    async def run_many(self, calls: Iterable[AgentCall], *, return_exceptions: bool = False) -> list[AgentResult | BaseException]:
        items = list(calls)
        semaphore = asyncio.Semaphore(self.max_concurrency) if self.max_concurrency else None

        async def one(call: AgentCall):
            if semaphore:
                async with semaphore:
                    return await self.run(call)
            return await self.run(call)

        return list(await asyncio.gather(*(one(call) for call in items), return_exceptions=return_exceptions))


async def run_agent(call: AgentCall) -> AgentResult:
    return await AgentRunner().run(call)


def run_agent_sync(call: AgentCall) -> AgentResult:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(run_agent(call))
    raise RuntimeError("run_agent_sync() cannot be called from a running event loop; await run_agent() instead")
