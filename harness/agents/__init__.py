"""Reusable adapters for running coding agents non-interactively."""

from .base import AgentCall, AgentResult
from .claude import ClaudeAdapter
from .codex import CodexAdapter
from .runner import (
    AgentRunner,
    AgentRunnerError,
    AgentTimeoutError,
    run_agent,
    run_agent_sync,
)

__all__ = [
    "AgentCall",
    "AgentResult",
    "AgentRunner",
    "AgentRunnerError",
    "AgentTimeoutError",
    "ClaudeAdapter",
    "CodexAdapter",
    "run_agent",
    "run_agent_sync",
]
