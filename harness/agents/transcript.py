"""Render an agent's streamed event log into a readable transcript and turn records.

Two outputs are written incrementally (flushed per event, so a killed run
still leaves everything up to the kill):

``transcript.md``  one block per assistant message: its text, a thinking
                   summary, and every tool call with its full input; tool
                   results follow, labelled by the call they answer, and
                   flagged when ``is_error``.
``turns.jsonl``    one normalized record per tool call::

    {"turn", "ts", "tool", "tool_use_id", "input_digest", "command",
     "input_preview", "result_chars", "is_error", "duration_ms",
     "is_finish"}

Both Claude Code ``stream-json`` and Codex ``exec --json`` event shapes are
understood; unknown events are kept in ``events.jsonl`` by the runner and
ignored here.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, TextIO

FINISH_TOOL_SUFFIX = "__finish"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _flatten(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, Mapping):
                if item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
                else:
                    parts.append(json.dumps(item, default=str))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content, default=str)


@dataclass
class _PendingCall:
    turn: int
    ts: float
    tool: str
    tool_use_id: str
    input: Any
    command: str | None


@dataclass
class TranscriptRenderer:
    directory: Path
    provider: str = "claude"
    model: str | None = None
    session_id: str | None = None
    turns: int = 0
    tool_calls: int = 0
    _md: TextIO | None = field(default=None, repr=False)
    _turns_file: TextIO | None = field(default=None, repr=False)
    _pending: dict[str, _PendingCall] = field(default_factory=dict)
    _codex_items: dict[str, tuple[float, int]] = field(default_factory=dict)
    _last_assistant_had_tool: bool | None = None

    def __post_init__(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._md = open(self.directory / "transcript.md", "w", encoding="utf-8")
        self._turns_file = open(self.directory / "turns.jsonl", "w", encoding="utf-8")
        self._write_md(f"# Agent transcript ({self.provider})\n")

    # -- output helpers -------------------------------------------------------

    def _write_md(self, text: str) -> None:
        assert self._md is not None
        self._md.write(text)
        if not text.endswith("\n"):
            self._md.write("\n")
        self._md.flush()

    def _write_turn(self, record: Mapping[str, Any]) -> None:
        assert self._turns_file is not None
        self._turns_file.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        self._turns_file.flush()
        self.tool_calls += 1

    def close(self) -> None:
        now = time.time()
        for call in list(self._pending.values()):
            self._emit_result(call, now, result_chars=None, is_error=None, unanswered=True)
        self._pending.clear()
        if self._md is not None:
            self._md.close()
            self._md = None
        if self._turns_file is not None:
            self._turns_file.close()
            self._turns_file = None

    # -- event dispatch -------------------------------------------------------

    def feed(self, event: Mapping[str, Any], ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        kind = event.get("type")
        if self.provider == "codex" or kind in {"thread.started", "turn.started", "turn.completed",
                                                "item.started", "item.completed", "item.updated"}:
            self._feed_codex(event, ts)
            return
        if kind == "system":
            self.model = event.get("model") or self.model
            self.session_id = event.get("session_id") or self.session_id
            if event.get("subtype") == "init":
                self._write_md(f"\n_session {self.session_id} · model {self.model}_\n")
        elif kind == "assistant":
            self._assistant(event, ts)
        elif kind == "user":
            self._user(event, ts)
        elif kind == "result":
            if self._last_assistant_had_tool is False:
                self._write_md("\n_(final message: no tool call, so the run ended here)_")
            self._write_md(f"\n---\n**result** · {event.get('subtype')} · turns={event.get('num_turns')} · "
                           f"cost=${event.get('total_cost_usd')}\n")

    def _assistant(self, event: Mapping[str, Any], ts: float) -> None:
        message = event.get("message", {})
        content = message.get("content", [])
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        self.turns += 1
        self.model = message.get("model") or self.model
        self._write_md(f"\n## Turn {self.turns} — assistant\n")
        has_tool = False
        for item in content:
            if not isinstance(item, Mapping):
                continue
            item_type = item.get("type")
            if item_type == "text":
                self._write_md(item.get("text", ""))
            elif item_type == "thinking":
                thought = str(item.get("thinking", ""))
                self._write_md(f"\n> _thinking ({len(thought)} chars)_: {thought[:300].strip()}"
                               + ("…" if len(thought) > 300 else ""))
            elif item_type == "tool_use":
                has_tool = True
                name = str(item.get("name", "?"))
                tool_input = item.get("input", {})
                command = tool_input.get("command") if isinstance(tool_input, Mapping) else None
                tool_id = str(item.get("id", ""))
                self._pending[tool_id] = _PendingCall(self.turns, ts, name, tool_id, tool_input, command)
                self._write_md(f"\n**tool_use** `{name}` (`{tool_id}`)\n```json\n"
                               f"{json.dumps(tool_input, indent=2, default=str)}\n```")
        self._last_assistant_had_tool = has_tool

    def _user(self, event: Mapping[str, Any], ts: float) -> None:
        message = event.get("message", {})
        content = message.get("content", [])
        if not isinstance(content, list):
            return
        for item in content:
            if not isinstance(item, Mapping) or item.get("type") != "tool_result":
                continue
            tool_id = str(item.get("tool_use_id", ""))
            text = _flatten(item.get("content"))
            is_error = bool(item.get("is_error"))
            call = self._pending.pop(tool_id, None)
            label = f"`{call.tool}` (`{tool_id}`)" if call else f"(`{tool_id}`)"
            self._write_md(f"\n**tool_result** {label}{' — ERROR' if is_error else ''}\n```\n{text}\n```")
            if call is not None:
                self._emit_result(call, ts, result_chars=len(text), is_error=is_error)
            else:
                self._write_turn({"turn": self.turns, "ts": ts, "tool": None, "tool_use_id": tool_id,
                                  "result_chars": len(text), "is_error": is_error, "unmatched": True})

    def _emit_result(self, call: _PendingCall, ts: float, *, result_chars: int | None,
                     is_error: bool | None, unanswered: bool = False) -> None:
        preview = call.command if call.command else json.dumps(call.input, default=str)
        self._write_turn({
            "turn": call.turn,
            "ts": call.ts,
            "tool": call.tool,
            "tool_use_id": call.tool_use_id,
            "input_digest": _digest(call.input),
            "command": call.command,
            "input_preview": preview[:400],
            "result_chars": result_chars,
            "is_error": is_error,
            "duration_ms": round((ts - call.ts) * 1000),
            "is_finish": call.tool.endswith(FINISH_TOOL_SUFFIX),
            "unanswered": unanswered,
        })

    # -- codex ----------------------------------------------------------------

    def _feed_codex(self, event: Mapping[str, Any], ts: float) -> None:
        kind = event.get("type")
        if kind == "thread.started":
            self.session_id = event.get("thread_id") or (event.get("thread") or {}).get("id") or self.session_id
            self.model = event.get("model") or self.model
            self._write_md(f"\n_thread {self.session_id}_\n")
        elif kind == "turn.started":
            self.turns += 1
            self._write_md(f"\n## Turn {self.turns} — assistant\n")
        elif kind in {"item.started", "item.completed"}:
            item = event.get("item", {})
            item_id = str(item.get("id", ""))
            item_type = item.get("type")
            if kind == "item.started":
                self._codex_items[item_id] = (ts, self.turns)
                return
            started_ts, turn = self._codex_items.pop(item_id, (ts, self.turns))
            if item_type == "agent_message":
                self._write_md(item.get("text", ""))
            elif item_type == "reasoning":
                text = str(item.get("text", ""))
                self._write_md(f"\n> _reasoning_: {text[:300]}")
            elif item_type in {"command_execution", "mcp_tool_call", "file_change"}:
                command = item.get("command")
                if item_type == "mcp_tool_call":
                    # Same naming as claude's MCP tools so metrics treat them alike.
                    tool = f"mcp__{item.get('server', 'mcp')}__{item.get('tool') or item.get('name') or '?'}"
                    tool_input = item.get("arguments") or {}
                    result = item.get("result") or {}
                    output = _flatten(result.get("content")) if isinstance(result, dict) else _flatten(result)
                    is_error = bool(item.get("error")) or item.get("status") == "failed"
                elif item_type == "file_change":
                    tool, tool_input = "Edit", {"changes": item.get("changes")}
                    output = json.dumps(item.get("changes", ""), default=str)
                    is_error = item.get("status") == "failed"
                else:
                    tool, tool_input = "Bash", {"command": command}
                    output = _flatten(item.get("aggregated_output") or "")
                    exit_code = item.get("exit_code")
                    is_error = bool(item.get("status") == "failed" or (exit_code not in (None, 0)))
                shown = command if command else json.dumps(tool_input, indent=2, default=str)
                self._write_md(f"\n**tool_use** `{tool}` (`{item_id}`)\n```\n{shown}\n```"
                               f"\n**tool_result** `{tool}`{' — ERROR' if is_error else ''}\n```\n{output}\n```")
                self._write_turn({
                    "turn": turn, "ts": started_ts, "tool": tool, "tool_use_id": item_id,
                    "input_digest": _digest(command or tool_input), "command": command,
                    "input_preview": (command or json.dumps(tool_input, default=str))[:400],
                    "result_chars": len(output), "is_error": is_error,
                    "duration_ms": round((ts - started_ts) * 1000),
                    "is_finish": tool.endswith(FINISH_TOOL_SUFFIX), "unanswered": False,
                })
        elif kind == "turn.completed":
            usage = event.get("usage") or {}
            self._write_md(f"\n_turn complete · usage {json.dumps(usage)}_")
        elif kind == "error":
            self._write_md(f"\n**error**: {event.get('message')}")
