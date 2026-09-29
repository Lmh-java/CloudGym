"""Codex CLI adapter for ``codex exec``."""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..pricing import codex_cost_usd
from .base import AgentCall, AgentResult


class CodexAdapter:
    provider = "codex"
    prompt_via_stdin = True

    def command(self, call: AgentCall, *, schema_path: Path | None, output_path: Path | None) -> list[str]:
        argv = [call.executable or "codex", "exec", "--json"]
        if call.safe_mode:
            argv += ["--sandbox", "read-only"]
        else:
            argv += ["--dangerously-bypass-approvals-and-sandbox"]
        for name, url in call.mcp_servers.items():
            argv += ["-c", f'mcp_servers.{name}.url="{url}"']
        if call.model:
            argv += ["--model", call.model]
        if schema_path:
            argv += ["--output-schema", str(schema_path)]
        if output_path:
            argv += ["--output-last-message", str(output_path)]
        argv.extend(call.native_args)
        argv.append("-")
        return argv

    def parse(self, call: AgentCall, *, stdout: str, stderr: str, output_text: str | None) -> AgentResult:
        events: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            if line.strip():
                events.append(json.loads(line))
        return self.parse_stream(call, events=events, stderr=stderr, output_text=output_text, stdout=stdout)

    def parse_stream(self, call: AgentCall, *, events: Sequence[Mapping[str, Any]], stderr: str,
                     output_text: str | None, stdout: str = "") -> AgentResult:
        session_id = next(
            (event.get("thread_id") or event.get("thread", {}).get("id")
             for event in events if event.get("type") == "thread.started"),
            None,
        )
        usage: dict[str, Any] = {}
        for event in reversed(events):
            if isinstance(event.get("usage"), dict):
                usage = event["usage"]
                break
        text = output_text if output_text is not None else ""
        if not text:
            text = "\n".join(
                str((event.get("item") or {}).get("text", ""))
                for event in events
                if event.get("type") == "item.completed" and (event.get("item") or {}).get("type") == "agent_message"
            ).strip()
        structured = json.loads(text) if call.output_schema is not None and text.strip() else None
        model = next((event.get("model") for event in events if event.get("type") == "thread.started" and event.get("model")), None)
        model = model or call.model or configured_model(call)
        completed = any(event.get("type") == "turn.completed" for event in events)
        failed = any(event.get("type") in ("turn.failed", "error") for event in events)
        # Codex reports tokens but never a price: the cost stored with the run is the
        # list-price estimate from harness.pricing (the Claude CLI's figure is list too).
        return AgentResult(call.provider, text, structured, session_id, usage, codex_cost_usd(model, usage),
                           stdout=stdout, stderr=stderr,
                           model=model, num_turns=round_trips(events) or None,
                           stop_reason="end_turn" if completed else ("error" if failed else None),
                           partial=not completed)


# Item types that each cost the model one round trip (a tool result comes back and the
# model is called again). Reasoning and intermediate messages ride along with these.
ROUND_TRIP_ITEMS = ("command_execution", "mcp_tool_call", "function_call", "file_change", "web_search")


def round_trips(events: Sequence[Mapping[str, Any]]) -> int:
    """Codex's equivalent of Claude's ``num_turns``.

    A codex session is one ``turn`` from thread start to the final message, so counting
    ``turn.completed`` reports 1 for every run and makes the two agents incomparable.
    Count model round trips instead: every tool-bearing item plus one for the closing
    message, which is what the Claude CLI's ``num_turns`` measures."""
    items = [(event.get("item") or {}).get("type") for event in events if event.get("type") == "item.completed"]
    trips = sum(1 for kind in items if kind in ROUND_TRIP_ITEMS)
    if any(kind == "agent_message" for kind in items):
        trips += 1
    return trips


def configured_model(call: AgentCall) -> str | None:
    """The default model from ``$CODEX_HOME/config.toml`` (codex's stream never names it)."""
    for item in call.native_args:
        if isinstance(item, str) and item.startswith("model="):
            return item.split("=", 1)[1].strip('"')
    home = call.env.get("CODEX_HOME") or os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
    path = Path(home) / "config.toml"
    try:
        return tomllib.loads(path.read_text()).get("model")
    except (OSError, tomllib.TOMLDecodeError):
        return None
