"""Shared contracts used by headless agent adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


@dataclass(frozen=True)
class AgentCall:
    """One non-interactive invocation of an installed agent CLI."""

    provider: str
    prompt: str
    cwd: Path | str | None = None
    model: str | None = None
    timeout: float = 120.0
    output_schema: Mapping[str, Any] | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    executable: str | None = None
    native_args: Sequence[str] = ()
    safe_mode: bool = True
    # name -> streamable-HTTP URL of MCP servers the agent may use.
    mcp_servers: Mapping[str, str] = field(default_factory=dict)
    # Extra tool names to allow (provider syntax), e.g. "Bash".
    allowed_tools: Sequence[str] = ()
    # False: start from a scrubbed environment (no ambient AWS identity) plus
    # ``env``; the harness injects exactly the credentials the actor may use.
    inherit_env: bool = True
    # When set, the adapter streams its event log and the runner writes
    # events.jsonl / transcript.md / turns.jsonl into this directory.
    transcript_dir: Path | None = None
    max_turns: int | None = None
    # When set, the process runs inside this bubblewrap sandbox (harness.agents.sandbox):
    # ``cwd`` is bound at the sandbox's mount point and nothing else of the host's home
    # or working tree exists inside.
    sandbox: Any | None = None

    @property
    def streaming(self) -> bool:
        return self.transcript_dir is not None


@dataclass(frozen=True)
class AgentResult:
    provider: str
    text: str
    structured_output: Any = None
    session_id: str | None = None
    usage: Mapping[str, Any] = field(default_factory=dict)
    cost_usd: float | None = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_seconds: float = 0.0
    model: str | None = None
    num_turns: int | None = None
    model_usage: Mapping[str, Any] = field(default_factory=dict)
    permission_denials: Sequence[Mapping[str, Any]] = ()
    duration_api_ms: int | None = None
    stop_reason: str | None = None
    # Paths written by the runner when streaming (None otherwise).
    events_path: Path | None = None
    transcript_path: Path | None = None
    turns_path: Path | None = None
    tool_calls: int | None = None
    partial: bool = False


class AgentAdapter(Protocol):
    provider: str
    prompt_via_stdin: bool

    def command(self, call: AgentCall, *, schema_path: Path | None, output_path: Path | None) -> list[str]: ...

    def parse(self, call: AgentCall, *, stdout: str, stderr: str, output_text: str | None) -> AgentResult: ...

    def parse_stream(self, call: AgentCall, *, events: Sequence[Mapping[str, Any]], stderr: str,
                     output_text: str | None) -> AgentResult: ...
